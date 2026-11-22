#!/usr/bin/env python3
"""Upload a CycloneDX SBOM, copy prior assessments, and apply current VEX."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, NoReturn


API_KEY = os.environ.get('DEPENDENCY_TRACK_API_KEY', '')
BASE_URL = os.environ.get('DEPENDENCY_TRACK_URL', '').rstrip('/')
PROJECT_NAME = os.environ.get('DEPENDENCY_TRACK_PROJECT_NAME', '')
PROJECT_VERSION = os.environ.get('DEPENDENCY_TRACK_PROJECT_VERSION', '')
CLASSIFIER = os.environ.get('DEPENDENCY_TRACK_CLASSIFIER', 'FIRMWARE').upper().replace(' ', '_')

VALID_CLASSIFIERS = {
    'APPLICATION',
    'FRAMEWORK',
    'LIBRARY',
    'CONTAINER',
    'PLATFORM',
    'OPERATING_SYSTEM',
    'DEVICE',
    'DEVICE_DRIVER',
    'FIRMWARE',
    'FILE',
    'MACHINE_LEARNING_MODEL',
    'DATA',
}


def fail(message: str) -> NoReturn:
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(1)


def request(
    path: str,
    *,
    method: str = 'GET',
    body: bytes | None = None,
    content_type: str | None = None,
) -> tuple[int, bytes]:
    headers = {'X-Api-Key': API_KEY, 'Accept': 'application/json'}
    if content_type:
        headers['Content-Type'] = content_type

    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/{path.lstrip('/')}",
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def require_success(status: int, body: bytes, operation: str) -> None:
    if 200 <= status < 300:
        return
    detail = body.decode('utf-8', errors='replace').strip()
    fail(f"{operation} failed with HTTP {status}: {detail}")


def decode_json(body: bytes, operation: str) -> Any:
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{operation} returned invalid JSON: {error}")


def get_json(path: str, operation: str) -> Any:
    status, body = request(path)
    require_success(status, body, operation)
    return decode_json(body, operation)


def multipart(fields: dict[str, str], file_field: str, file_path: Path) -> tuple[bytes, str]:
    boundary = f"----dependency-track-{uuid.uuid4().hex}"
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                value.encode(),
                b'\r\n',
            ]
        )
    chunks.extend(
        [
            f"--{boundary}\r\n".encode(),
            (
                f'Content-Disposition: form-data; name="{file_field}"; '
                f'filename="{file_path.name}"\r\n'
            ).encode(),
            b'Content-Type: application/json\r\n\r\n',
            file_path.read_bytes(),
            b'\r\n',
            f"--{boundary}--\r\n".encode(),
        ]
    )
    return b''.join(chunks), f"multipart/form-data; boundary={boundary}"


def wait_for_token(token: str, attempts: int = 60, delay: int = 5) -> bool:
    if not token:
        return False
    for _ in range(attempts):
        try:
            status, body = request(f"event/token/{token}")
            event = json.loads(body) if 200 <= status < 300 else {}
            if event.get('processing') is False:
                return True
        except (OSError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError):
            pass
        time.sleep(delay)
    return False


def analyzed_vulnerabilities(vex: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        vulnerability
        for vulnerability in vex.get('vulnerabilities', [])
        if (vulnerability.get('analysis') or {}).get('state') is not None
    ]


AUDIT_FIELDS = (
    'analysisState', 'analysisJustification', 'analysisResponse',
    'analysisDetails', 'isSuppressed',
)


def finding_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    component = finding['component']
    vulnerability = finding['vulnerability']
    # Versions and sources must match: a CVE assessment is component-specific.
    return (
        vulnerability['source'], vulnerability['vulnId'],
        component.get('group') or '', component['name'], component.get('version'),
    )


def repository_package(purl: str) -> tuple[str, str, str] | None:
    """Identify a VCS package independently of its commit, retaining its path."""
    coordinates, _, subpath = purl.partition('#')
    coordinates, _, qualifiers = coordinates.partition('?')
    package, separator, revision = coordinates.rpartition('@')
    if not separator or not revision or not package.startswith(('pkg:github/', 'pkg:gitlab/')):
        return None
    return package, qualifiers, subpath


def compatible_component(previous: dict[str, Any], current: dict[str, Any]) -> bool:
    old_purl, new_purl = previous.get('purl'), current.get('purl')
    if not old_purl or not new_purl or old_purl == new_purl:
        return True
    # esp-idf-sbom derives VCS PURLs from the build commit. A patched build
    # can change that commit without changing the assessed package release.
    # Require the same explicit release CPE and repository package (including
    # subpath and qualifiers); never drop versions from registry PURLs.
    cpe = previous.get('cpe') or ''
    parts = cpe.split(':')
    return bool(
        cpe == current.get('cpe') and cpe.startswith('cpe:2.3:')
        and len(parts) == 13 and parts[5] not in ('', '*', '-')
        and previous.get('version') and previous.get('version') == current.get('version')
        and repository_package(old_purl) is not None
        and repository_package(old_purl) == repository_package(new_purl)
    )


def report_unmatched_audits(audits: list[dict[str, Any]], findings: list[dict[str, Any]]) -> None:
    unmatched = []
    for audit in audits:
        previous = audit['finding']
        if any(finding_key(previous) == finding_key(item)
               and compatible_component(previous['component'], item['component']) for item in findings):
            continue
        candidates = [item for item in findings
                      if item['vulnerability']['vulnId'] == previous['vulnerability']['vulnId']]
        differences = sorted({
            field for item in candidates
            for section, fields in (('component', ('group', 'name', 'version', 'purl', 'cpe')),
                                    ('vulnerability', ('source',)))
            for field in fields
            if (item[section].get(field) or '') != (previous[section].get(field) or '')
        })
        reason = f"different {', '.join(differences)}" if candidates else 'no current finding for this vulnerability'
        entry = {'version': audit['version'], 'reason': reason,
                 'previous': previous, 'current_candidates': candidates}
        unmatched.append(entry)
        component = previous['component']
        print(f"Skipped prior audit: {previous['vulnerability']['source']} "
              f"{previous['vulnerability']['vulnId']} on {component['name']} "
              f"{component.get('version')} from {audit['version']}: {reason}")
    Path('dtrack-audit-report.json').write_text(
        json.dumps({'prior_decisions': len(audits), 'unmatched': unmatched}, indent=2) + '\n',
        encoding='utf-8',
    )


def read_analysis(
    project_uuid: str, finding: dict[str, Any], *, allow_missing: bool = False,
) -> dict[str, Any]:
    query = urllib.parse.urlencode({
        'project': project_uuid, 'component': finding['component']['uuid'],
        'vulnerability': finding['vulnerability']['uuid'],
    })
    status, body = request(f"analysis?{query}")
    # v5 returns 404 for a valid finding that has not been assessed yet.
    # Other 404s (missing project/component/vulnerability) are real errors.
    if allow_missing and status == 404 and body.strip() == b'No analysis exists.':
        return {}
    require_success(status, body, 'reading audit decisions')
    return decode_json(body, 'reading audit decisions') or {}


def get_findings(project_uuid: str) -> list[dict[str, Any]]:
    findings = []
    page = 1
    while True:
        batch = get_json(
            f"finding/project/{project_uuid}?suppressed=true&pageSize=100&pageNumber={page}",
            'reading project findings',
        )
        findings.extend(batch)
        if len(batch) < 100:
            return findings
        page += 1


def find_previous_audits() -> list[dict[str, Any]]:
    projects = []
    page = 1
    while True:
        query = urllib.parse.urlencode({'name': PROJECT_NAME, 'pageSize': 100, 'pageNumber': page})
        batch = get_json(f"project?{query}", 'listing prior project versions')
        projects.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    candidates = sorted(
        (project for project in projects
         if project.get('name') == PROJECT_NAME and project.get('version') != PROJECT_VERSION),
        key=lambda project: project.get('lastBomImport') or 0,
        reverse=True,
    )
    inherited = {}
    for project in candidates:
        version, project_uuid = project.get('version'), project['uuid']
        print(f"Checking audit decisions from version {version} ({project_uuid})")
        findings = get_findings(project_uuid)
        audits = []
        for finding in findings:
            summary = finding.get('analysis') or {}
            if summary.get('state', 'NOT_SET') == 'NOT_SET' and not summary.get('isSuppressed'):
                continue
            analysis = read_analysis(project_uuid, finding)
            if analysis.get('analysisState', 'NOT_SET') == 'NOT_SET' and not analysis.get('isSuppressed'):
                continue
            audits.append({
                'finding': finding,
                'analysis': {field: analysis[field] for field in AUDIT_FIELDS if analysis.get(field) is not None},
                'comments': analysis.get('analysisComments') or [],
                'version': version,
            })
        if audits:
            print(f"Found {len(audits)} audit decisions in version {version}")
            for audit in audits:
                # Fill gaps left by unsuccessful uploads; newer decisions win.
                component = audit['finding']['component']
                inherited.setdefault((finding_key(audit['finding']), component.get('purl'),
                                      component.get('cpe')), audit)
    if not inherited:
        print('No previous audit decisions found; no assessments to carry forward')
    return list(inherited.values())


def upload_bom(sbom_path: Path) -> tuple[str, str]:
    body, content_type = multipart(
        {
            'autoCreate': 'true',
            'projectName': PROJECT_NAME,
            'projectVersion': PROJECT_VERSION,
        },
        'bom',
        sbom_path,
    )
    status, response_body = request('bom', method='POST', body=body, content_type=content_type)
    Path('dtrack-bom-response.json').write_bytes(response_body)
    require_success(status, response_body, 'uploading the SBOM')
    response = decode_json(response_body, 'uploading the SBOM')
    return response.get('projectUuid', ''), response.get('token', '')


def set_classifier(project_uuid: str) -> None:
    if CLASSIFIER not in VALID_CLASSIFIERS:
        print(f"Warning: unknown classifier {CLASSIFIER!r}; classifier was not changed")
        return
    body = json.dumps({'classifier': CLASSIFIER}).encode()
    status, response_body = request(
        f"project/{project_uuid}", method='PATCH', body=body, content_type='application/json'
    )
    if status not in (200, 304):
        detail = response_body.decode('utf-8', errors='replace').strip()
        print(f"Warning: setting classifier failed with HTTP {status}: {detail}")


def import_vex(vex_path: Path) -> bool:
    body, content_type = multipart(
        {'projectName': PROJECT_NAME, 'projectVersion': PROJECT_VERSION}, 'vex', vex_path
    )
    status, response_body = request('vex', method='POST', body=body, content_type=content_type)
    if not 200 <= status < 300:
        detail = response_body.decode('utf-8', errors='replace').strip()
        print(f"Warning: VEX import failed with HTTP {status}: {detail}")
        return False
    response = decode_json(response_body, 'importing VEX')
    if not wait_for_token(response.get('token', '')):
        print('Warning: VEX processing was not confirmed within 300 seconds')
        return False
    return True


def carry_forward_audits(project_uuid: str, audits: list[dict[str, Any]]) -> None:
    expected: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for audit in audits:
        expected.setdefault(finding_key(audit['finding']), []).append(audit)
    last_snapshot = None
    stable_count = 0
    commented = set()
    print('Waiting for findings and copying prior audit decisions')
    for _ in range(30):
        findings = get_findings(project_uuid)
        snapshot = {(item['component']['uuid'], item['vulnerability']['uuid']) for item in findings}
        stable_count = stable_count + 1 if snapshot == last_snapshot else 0
        last_snapshot = snapshot
        matching = 0
        pending = 0
        for finding in findings:
            current_component = finding['component']
            audit = next((candidate for candidate in expected.get(finding_key(finding), [])
                          if compatible_component(candidate['finding']['component'], current_component)), None)
            if audit is None:
                continue
            matching += 1
            analysis = read_analysis(project_uuid, finding, allow_missing=True)
            if all(analysis.get(field) == value for field, value in audit['analysis'].items()):
                continue
            payload = {
                'project': project_uuid,
                'component': current_component['uuid'],
                'vulnerability': finding['vulnerability']['uuid'],
                **audit['analysis'],
            }
            target = (current_component['uuid'], finding['vulnerability']['uuid'])
            if audit.get('comments') and target not in commented:
                history = '\n'.join(
                    f"{comment.get('commenter', '')}: {comment.get('comment', '')}"
                    for comment in audit['comments']
                )
                payload['comment'] = f"Copied from version {audit['version']}:\n{history}"
            status, body = request('analysis', method='PUT', body=json.dumps(payload).encode(),
                                   content_type='application/json')
            require_success(status, body, 'copying prior audit decisions')
            commented.add(target)
            pending += 1
        print(f"Findings: {len(findings)} total, {matching} prior audits, {pending} awaiting verification")
        if not pending and findings and stable_count >= 2:
            print(f"Carried forward and verified {matching} matching audit decisions")
            break
        if not findings and stable_count >= 12:
            print('No findings reported for this project version')
            break
        time.sleep(10)
    else:
        fail('audit carry-forward could not be confirmed before the timeout')
    report_unmatched_audits(audits, findings)
    status, body = request(f"metrics/project/{project_uuid}/refresh")
    require_success(status, body, 'refreshing project metrics')


def import_current_audits(project_uuid: str, sbom_path: Path, sbom: dict[str, Any]) -> None:
    # Older Dependency-Track importers require source.name. esp-idf-sbom
    # emits CVE exclusions without it; these refer to NVD findings.
    vex = json.loads(json.dumps(sbom))
    for decision in analyzed_vulnerabilities(vex):
        if not (decision.get('source') or {}).get('name'):
            if not decision.get('id', '').startswith('CVE-'):
                fail(f"current VEX assessment has no vulnerability source: {decision.get('id')}")
            decision['source'] = {'name': 'NVD'}
    vex_path = sbom_path.with_name('current.vex.json')
    if vex_path == sbom_path:
        fail('the SBOM input must not be named current.vex.json')
    decisions = analyzed_vulnerabilities(vex)
    if not decisions:
        print('Current SBOM contains no audit decisions to import')
        return
    vex_path.write_text(json.dumps(vex, indent=2) + '\n', encoding='utf-8')

    components = {item.get('bom-ref'): item for item in sbom.get('components', [])}
    expected = {
        (decision['id'], decision['source']['name'], component.get('group') or '', component.get('name'), component.get('version')): (
            decision['analysis']['state'].upper(),
            (decision['analysis'].get('detail') or '').strip(),
        )
        for decision in decisions
        for affected in decision.get('affects', [])
        if (component := components.get(affected.get('ref'))) is not None
    }
    last_findings = None
    stable_count = 0
    imported = False

    print('Waiting for findings and applying current SBOM audit decisions')
    for _ in range(30):
        findings = get_findings(project_uuid)
        # Findings can arrive after BOM processing and in multiple batches.
        snapshot = {(item['component']['uuid'], item['vulnerability']['uuid']) for item in findings}
        stable_count = stable_count + 1 if snapshot == last_findings else 0
        changed = snapshot != last_findings
        last_findings = snapshot
        matching = []
        pending = []
        for item in findings:
            component = item['component']
            key = (
                item['vulnerability']['vulnId'], item['vulnerability'].get('source'), component.get('group') or '',
                component.get('name'), component.get('version'),
            )
            if key not in expected:
                continue
            matching.append(item)
            state, detail = expected[key]
            analysis = item.get('analysis') or {}
            # The findings API exposes state and suppression, but not details.
            if analysis.get('state') == state and detail:
                query = urllib.parse.urlencode({
                    'project': project_uuid, 'component': component['uuid'],
                    'vulnerability': item['vulnerability']['uuid'],
                })
                audit = get_json(f"analysis?{query}", 'reading current audit details') or {}
                # /analysis uses different field names than /finding.
                analysis = {
                    'state': audit.get('analysisState'),
                    'details': audit.get('analysisDetails'),
                }
            if analysis.get('state') != state or (detail and analysis.get('details') != detail):
                pending.append(item)

        print(f"Findings: {len(findings)} total, {len(matching)} current audits, {len(pending)} pending")
        if findings and (not imported or changed or pending):
            if not import_vex(vex_path):
                fail('current SBOM VEX import could not be confirmed')
            imported = True
        elif imported and stable_count >= 2:
            print(f"Applied current SBOM VEX; verified {len(matching)} matching audit decisions")
            break
        time.sleep(10)
    else:
        fail('current SBOM audit import could not be verified before the timeout')

    status, body = request(f"metrics/project/{project_uuid}/refresh")
    if not 200 <= status < 300:
        print(f"Warning: metrics refresh failed with HTTP {status}: {body.decode(errors='replace')}")


def main() -> None:
    if len(sys.argv) != 2:
        fail(f"usage: {Path(sys.argv[0]).name} <cyclonedx-sbom.json>")
    missing = [
        name
        for name, value in {
            'DEPENDENCY_TRACK_URL': BASE_URL,
            'DEPENDENCY_TRACK_API_KEY': API_KEY,
            'DEPENDENCY_TRACK_PROJECT_NAME': PROJECT_NAME,
            'DEPENDENCY_TRACK_PROJECT_VERSION': PROJECT_VERSION,
        }.items()
        if not value
    ]
    if missing:
        fail(f"missing required environment variables: {', '.join(missing)}")

    sbom_path = Path(sys.argv[1])
    if not sbom_path.is_file() or sbom_path.stat().st_size == 0:
        fail(f"SBOM does not exist or is empty: {sbom_path}")
    try:
        sbom = json.loads(sbom_path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"SBOM is not valid JSON: {error}")
    if sbom.get('bomFormat') != 'CycloneDX':
        fail('SBOM is not in CycloneDX JSON format')

    print(f"Publishing {PROJECT_NAME} {PROJECT_VERSION} to {BASE_URL}")
    previous_audits = find_previous_audits()
    project_uuid, token = upload_bom(sbom_path)
    if not project_uuid or not token:
        fail('the BOM upload response did not include projectUuid and token')

    print(f"Waiting for BOM processing (token {token})")
    if not wait_for_token(token):
        fail('BOM processing was not confirmed within 300 seconds')
    set_classifier(project_uuid)
    if previous_audits:
        carry_forward_audits(project_uuid, previous_audits)
    import_current_audits(project_uuid, sbom_path, sbom)

    print(f"Dependency-Track project UUID: {project_uuid}")


if __name__ == '__main__':
    try:
        main()
    except (OSError, TimeoutError) as error:
        fail(str(error))
