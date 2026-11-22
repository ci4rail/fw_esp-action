"""Offline regression tests for Dependency-Track VEX publishing."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('dependency_track', Path(__file__).with_name('dependency_track.py'))
dt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dt)


def make_sbom():
    return {
        'bomFormat': 'CycloneDX',
        'components': [{'bom-ref': 'kernel', 'name': 'freertos', 'version': '10.5.1'}],
        'vulnerabilities': [{
            'id': 'CVE-2026-77234',
            'affects': [{'ref': 'kernel'}],
            'analysis': {'state': 'not_affected', 'detail': 'MPU wrappers are disabled.'},
        }],
    }


def make_finding(source='NVD', component_uuid='component'):
    return {
        'component': {'uuid': component_uuid, 'name': 'freertos', 'version': '10.5.1'},
        'vulnerability': {'uuid': source + '-vuln', 'vulnId': 'CVE-2026-77234', 'source': source},
        'analysis': {'state': 'EXPLOITABLE', 'isSuppressed': False},
    }


class CurrentVexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'sbom.cdx.json'
        self.sbom = make_sbom()
        self.path.write_text(json.dumps(self.sbom))
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.enterContext(contextlib.redirect_stderr(io.StringIO()))
        self.enterContext(patch.object(dt.time, 'sleep'))
        self.refresh = self.enterContext(patch.object(dt, 'request', return_value=(200, b'{}')))

    def test_delayed_findings_and_later_batch_override_prior_decisions(self):
        first = make_finding()
        second = make_finding(component_uuid='second-component')
        unrelated_source = make_finding(source='OSV')
        batches = [[], [first, unrelated_source], [first, second, unrelated_source]]
        imports = []
        details = {}

        def get_json(path, operation):
            if path.startswith('finding/'):
                return batches.pop(0) if len(batches) > 1 else batches[0]
            query = dt.urllib.parse.parse_qs(path.split('?', 1)[1])
            return details[query['component'][0]]

        def import_vex(path):
            # The original SBOM and in-memory data must remain unchanged.
            self.assertEqual(json.loads(self.path.read_text()), self.sbom)
            document = json.loads(path.read_text())
            self.assertEqual(document['vulnerabilities'][0]['source'], {'name': 'NVD'})
            imports.append(document)
            for finding in (first, second):
                finding['analysis'] = {'state': 'NOT_AFFECTED', 'isSuppressed': True}
                details[finding['component']['uuid']] = {
                    'analysisState': 'NOT_AFFECTED', 'analysisDetails': 'MPU wrappers are disabled.',
                }
            return True

        with patch.object(dt, 'get_json', side_effect=get_json), patch.object(dt, 'import_vex', side_effect=import_vex):
            dt.import_current_audits('project', self.path, self.sbom)
        self.assertEqual(len(imports), 2)
        self.assertEqual(unrelated_source['analysis']['state'], 'EXPLOITABLE')
        self.refresh.assert_called_once_with('metrics/project/project/refresh')

    def test_existing_state_with_old_details_is_updated(self):
        finding = make_finding()
        finding['analysis']['state'] = 'NOT_AFFECTED'
        details = {'analysisState': 'NOT_AFFECTED', 'analysisDetails': 'old assessment'}

        def get_json(path, operation):
            return [finding] if path.startswith('finding/') else details

        def import_vex(path):
            details['analysisDetails'] = 'MPU wrappers are disabled.'
            return True

        with patch.object(dt, 'get_json', side_effect=get_json), patch.object(dt, 'import_vex', side_effect=import_vex) as upload:
            dt.import_current_audits('project', self.path, self.sbom)
        upload.assert_called_once()

    def test_no_assessments_skips_polling_and_import(self):
        with patch.object(dt, 'get_json') as read, patch.object(dt, 'import_vex') as upload:
            dt.import_current_audits('project', self.path, {'bomFormat': 'CycloneDX'})
        read.assert_not_called()
        upload.assert_not_called()

    def test_import_failure_fails_the_run(self):
        with patch.object(dt, 'get_json', return_value=[make_finding()]), patch.object(dt, 'import_vex', return_value=False):
            with self.assertRaises(SystemExit):
                dt.import_current_audits('project', self.path, self.sbom)
        self.refresh.assert_not_called()

    def test_vex_processing_timeout_is_reported_as_failure(self):
        with patch.object(dt, 'request', return_value=(200, b'{"token": "vex-token"}')), patch.object(dt, 'wait_for_token', return_value=False):
            self.assertFalse(dt.import_vex(self.path))

    def test_timeout_does_not_import_before_findings_exist(self):
        with patch.object(dt, 'get_json', return_value=[]) as read, patch.object(dt, 'import_vex') as upload:
            with self.assertRaises(SystemExit):
                dt.import_current_audits('project', self.path, self.sbom)
        self.assertEqual(read.call_count, 30)
        upload.assert_not_called()

    def test_explicit_source_is_preserved(self):
        self.sbom['vulnerabilities'][0]['source'] = {'name': 'OSV'}
        finding = make_finding(source='OSV')
        analysis = {'analysisState': 'NOT_AFFECTED', 'analysisDetails': 'MPU wrappers are disabled.'}

        def get_json(path, operation):
            return [finding] if path.startswith('finding/') else analysis

        def import_vex(path):
            document = json.loads(path.read_text())
            self.assertEqual(document['vulnerabilities'][0]['source'], {'name': 'OSV'})
            finding['analysis']['state'] = 'NOT_AFFECTED'
            return True

        with patch.object(dt, 'get_json', side_effect=get_json), patch.object(dt, 'import_vex', side_effect=import_vex):
            dt.import_current_audits('project', self.path, self.sbom)

    def test_applied_audit_uses_analysis_endpoint_fields_without_reimporting(self):
        finding = make_finding()
        finding['analysis'] = {'state': 'NOT_AFFECTED', 'isSuppressed': True}
        audit = {
            'analysisState': 'NOT_AFFECTED',
            'analysisDetails': 'MPU wrappers are disabled.',
            'isSuppressed': True,
        }

        def get_json(path, operation):
            return [finding] if path.startswith('finding/') else audit

        with patch.object(dt, 'get_json', side_effect=get_json) as read, patch.object(dt, 'import_vex', return_value=True) as upload:
            dt.import_current_audits('project', self.path, self.sbom)
        upload.assert_called_once()
        self.assertEqual(sum(call.args[0].startswith('finding/') for call in read.call_args_list), 3)
        self.refresh.assert_called_once()

    def test_main_applies_current_assessments_after_previous(self):
        calls = []
        with contextlib.ExitStack() as stack:
            for name in ('API_KEY', 'BASE_URL', 'PROJECT_NAME', 'PROJECT_VERSION'):
                stack.enter_context(patch.object(dt, name, 'test'))
            stack.enter_context(patch.object(dt.sys, 'argv', ['dependency_track.py', str(self.path)]))
            stack.enter_context(patch.object(dt, 'find_previous_audits', return_value=[{'analysis': {}}]))
            stack.enter_context(patch.object(dt, 'upload_bom', return_value=('project', 'token')))
            stack.enter_context(patch.object(dt, 'wait_for_token', return_value=True))
            stack.enter_context(patch.object(dt, 'set_classifier'))
            stack.enter_context(patch.object(dt, 'carry_forward_audits', side_effect=lambda *args: calls.append('previous')))
            stack.enter_context(patch.object(dt, 'import_current_audits', side_effect=lambda *args: calls.append('current')))
            dt.main()
        self.assertEqual(calls, ['previous', 'current'])


class PriorAuditTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.output))
        self.enterContext(contextlib.redirect_stderr(io.StringIO()))
        self.enterContext(patch.object(dt.time, 'sleep'))
        self.enterContext(patch.object(dt, 'PROJECT_NAME', 'firmware'))
        self.enterContext(patch.object(dt, 'PROJECT_VERSION', 'dt.5'))
        self.report = self.enterContext(patch.object(dt.Path, 'write_text'))
        self.finding = make_finding()
        self.analysis = {
            'analysisState': 'NOT_AFFECTED',
            'analysisJustification': 'CODE_NOT_REACHABLE',
            'analysisResponse': 'NOT_SET',
            'analysisDetails': 'MPU wrappers disabled',
            'isSuppressed': True,
        }
        self.audits = [{
            'finding': make_finding(component_uuid='old-component'),
            'analysis': self.analysis.copy(), 'version': 'rc.4',
            'comments': [{'commenter': 'reviewer', 'comment': 'Reviewed firmware configuration'}],
        }]

    def test_reads_suppressed_prior_audits_without_vex_export(self):
        self.finding['analysis'] = {'state': 'NOT_AFFECTED', 'isSuppressed': True}
        projects = [
            {'name': 'other', 'uuid': 'wrong', 'version': 'rc.9', 'lastBomImport': 99},
            {'name': 'firmware', 'uuid': 'current', 'version': 'dt.5', 'lastBomImport': 20},
            {'name': 'firmware', 'uuid': 'previous', 'version': 'rc.4', 'lastBomImport': 10},
        ]
        def get_json(path, operation):
            if path.startswith('project?'):
                return projects
            self.assertTrue(path.startswith('finding/project/previous?suppressed=true'))
            return [self.finding]
        with patch.object(dt, 'get_json', side_effect=get_json), patch.object(dt, 'read_analysis', return_value=self.analysis):
            audits = dt.find_previous_audits()
        self.assertEqual(audits[0]['analysis'], self.analysis)
        self.assertEqual(audits[0]['version'], 'rc.4')

    def test_prior_read_failure_fails_instead_of_silently_skipping(self):
        with patch.object(dt, 'request', return_value=(403, b'Forbidden')):
            with self.assertRaises(SystemExit):
                dt.find_previous_audits()

    def test_older_version_fills_failed_upload_gaps_and_newer_decision_wins(self):
        self.finding['analysis']['state'] = 'NOT_AFFECTED'
        older_finding = make_finding(component_uuid='older-component')
        older_finding['analysis']['state'] = 'NOT_AFFECTED'
        missing_finding = make_finding(component_uuid='missing-component')
        missing_finding['vulnerability']['vulnId'] = 'CVE-2026-99999'
        missing_finding['analysis']['state'] = 'NOT_AFFECTED'
        projects = [
            {'name': 'firmware', 'uuid': 'dt4', 'version': 'dt.4', 'lastBomImport': 20},
            {'name': 'firmware', 'uuid': 'rc4', 'version': 'rc.4', 'lastBomImport': 10},
        ]
        def get_findings(project_uuid):
            return [self.finding] if project_uuid == 'dt4' else [older_finding, missing_finding]
        with patch.object(dt, 'get_json', return_value=projects), patch.object(dt, 'get_findings', side_effect=get_findings), patch.object(dt, 'read_analysis', return_value=self.analysis):
            audits = dt.find_previous_audits()
        self.assertEqual(len(audits), 2)
        self.assertEqual([audit['version'] for audit in audits], ['dt.4', 'rc.4'])

    def test_copies_and_verifies_fields_and_comments_after_delayed_findings(self):
        current = {'analysisState': 'NOT_AFFECTED', 'analysisDetails': 'old assessment', 'isSuppressed': False}
        batches = [[], [self.finding]]
        writes = []
        def get_findings(project_uuid):
            return batches.pop(0) if len(batches) > 1 else batches[0]
        def request(path, **kwargs):
            if path == 'analysis':
                payload = json.loads(kwargs['body'])
                writes.append(payload)
                current.update({field: payload[field] for field in dt.AUDIT_FIELDS})
            return 200, b'{}'
        with patch.object(dt, 'get_findings', side_effect=get_findings), patch.object(dt, 'read_analysis', side_effect=lambda *args, **kwargs: current), patch.object(dt, 'request', side_effect=request):
            dt.carry_forward_audits('new-project', self.audits)
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]['project'], 'new-project')
        self.assertEqual(writes[0]['component'], 'component')
        self.assertIn('Copied from version rc.4', writes[0]['comment'])
        for field in dt.AUDIT_FIELDS:
            self.assertEqual(writes[0][field], self.analysis[field])

    def test_unassessed_target_404_is_copied_and_verified(self):
        current = None
        writes = []

        def request(path, **kwargs):
            nonlocal current
            if path.startswith('analysis?'):
                if current is None:
                    return 404, b'No analysis exists.'
                return 200, json.dumps(current).encode()
            if path == 'analysis':
                payload = json.loads(kwargs['body'])
                writes.append(payload)
                current = {field: payload[field] for field in dt.AUDIT_FIELDS}
            return 200, b'{}'

        with patch.object(dt, 'get_findings', return_value=[self.finding]), patch.object(dt, 'request', side_effect=request):
            dt.carry_forward_audits('new-project', self.audits)
        self.assertEqual(len(writes), 1)
        self.assertEqual(current, self.analysis)

    def test_prior_missing_analysis_and_other_target_errors_remain_fatal(self):
        cases = [
            (False, 404, b'No analysis exists.'),
            (True, 404, b'The component could not be found.'),
            (True, 403, b'Forbidden'),
            (True, 500, b'Internal server error'),
        ]
        for allow_missing, status, body in cases:
            with self.subTest(allow_missing=allow_missing, status=status, body=body), patch.object(dt, 'request', return_value=(status, body)):
                with self.assertRaises(SystemExit):
                    dt.read_analysis('project', self.finding, allow_missing=allow_missing)

    def test_same_cve_on_different_source_component_or_version_is_not_copied(self):
        findings = []
        for field, value in [('source', 'OSV'), ('name', 'other-library'), ('version', '11.0')]:
            finding = make_finding()
            target = finding['vulnerability'] if field == 'source' else finding['component']
            target[field] = value
            findings.append(finding)
        with patch.object(dt, 'get_findings', return_value=findings), patch.object(dt, 'read_analysis') as read, patch.object(dt, 'request', return_value=(200, b'{}')) as request:
            dt.carry_forward_audits('project', self.audits)
        read.assert_not_called()
        request.assert_called_once_with('metrics/project/project/refresh')

    def test_changed_purl_is_not_copied(self):
        self.audits[0]['finding']['component']['purl'] = 'pkg:generic/library@old'
        self.finding['component']['purl'] = 'pkg:generic/library@new'
        with patch.object(dt, 'get_findings', return_value=[self.finding]), patch.object(dt, 'read_analysis') as read, patch.object(dt, 'request', return_value=(200, b'{}')):
            dt.carry_forward_audits('project', self.audits)
        read.assert_not_called()

    def test_seventeen_audits_survive_ten_changed_build_commit_purls(self):
        findings, audits, current, writes = [], [], {}, []
        for index in range(17):
            old = make_finding(component_uuid=f'old-{index}')
            new = make_finding(component_uuid=f'new-{index}')
            for finding in (old, new):
                finding['vulnerability']['vulnId'] = f'CVE-2026-{index:05}'
                finding['component'].update({
                    'cpe': 'cpe:2.3:a:espressif:esp-idf:5.5.4:*:*:*:*:*:*:*',
                    'version': '5.5.4', 'name': 'esp-idf',
                    'purl': 'pkg:github/espressif/esp-idf@old-commit',
                })
            if index >= 7:
                new['component']['purl'] = 'pkg:github/espressif/esp-idf@new-commit'
            findings.append(new)
            audits.append({'finding': old, 'analysis': self.analysis.copy(), 'version': 'rc.4'})

        def request(path, **kwargs):
            if path == 'analysis':
                payload = json.loads(kwargs['body'])
                writes.append(payload)
                current[payload['component']] = {field: payload[field] for field in dt.AUDIT_FIELDS}
            return 200, b'{}'

        with patch.object(dt, 'get_findings', return_value=findings), patch.object(dt, 'request', side_effect=request), patch.object(dt, 'read_analysis', side_effect=lambda project, finding, **kwargs: current.get(finding['component']['uuid'], {})):
            dt.carry_forward_audits('project', audits)
        self.assertEqual(len(writes), 17)
        self.assertIn('verified 17 matching audit decisions', self.output.getvalue())
        self.assertEqual(json.loads(self.report.call_args.args[0])['unmatched'], [])

    def test_changed_commit_requires_same_release_cpe_and_repository_package(self):
        old = {'name': 'esp-idf', 'version': '5.5.4',
               'purl': 'pkg:github/espressif/esp-idf@old#components/freertos',
               'cpe': 'cpe:2.3:a:espressif:esp-idf:5.5.4:*:*:*:*:*:*:*'}
        current = {**old, 'purl': 'pkg:github/espressif/esp-idf@new#components/freertos'}
        self.assertTrue(dt.compatible_component(old, current))
        for changes in (
            {'cpe': None},
            {'cpe': 'cpe:2.3:a:espressif:esp-idf:5.5.5:*:*:*:*:*:*:*'},
            {'version': '5.5.5'},
            {'purl': 'pkg:github/other/esp-idf@new#components/freertos'},
            {'purl': 'pkg:github/espressif/esp-idf@new#components/mbedtls'},
            {'purl': 'pkg:github/espressif/esp-idf@new?target=other#components/freertos'},
        ):
            with self.subTest(changes=changes):
                self.assertFalse(dt.compatible_component(old, {**current, **changes}))
        for version in ('*', '-'):
            cpe = f'cpe:2.3:a:espressif:esp-idf:{version}:*:*:*:*:*:*:*'
            self.assertFalse(dt.compatible_component({**old, 'cpe': cpe}, {**current, 'cpe': cpe}))
        self.assertFalse(dt.compatible_component(
            {**old, 'purl': 'pkg:pypi/example@1'}, {**current, 'purl': 'pkg:pypi/example@2'}))

    def test_unmatched_audits_report_actual_identity_differences(self):
        self.finding['component']['version'] = '11.0'
        with patch.object(dt, 'get_findings', return_value=[self.finding]), patch.object(dt, 'request', return_value=(200, b'{}')):
            dt.carry_forward_audits('project', self.audits)
        report = json.loads(self.report.call_args.args[0])
        self.assertEqual(report['prior_decisions'], 1)
        self.assertEqual(report['unmatched'][0]['reason'], 'different version')
        self.assertEqual(report['unmatched'][0]['current_candidates'], [self.finding])
        self.assertIn('Skipped prior audit:', self.output.getvalue())

    def test_older_compatible_identity_is_not_discarded_by_newer_incompatible_audit(self):
        old = self.audits[0]
        old['finding']['component']['purl'] = 'pkg:generic/correct@1'
        self.finding['component']['purl'] = 'pkg:generic/correct@1'
        newer = {**old, 'version': 'rc.5',
                 'finding': {**old['finding'], 'component': {**old['finding']['component'], 'purl': 'pkg:generic/other@1'}}}
        with patch.object(dt, 'get_json', return_value=[
            {'name': 'firmware', 'uuid': 'rc5', 'version': 'rc.5', 'lastBomImport': 20},
            {'name': 'firmware', 'uuid': 'rc4', 'version': 'rc.4', 'lastBomImport': 10},
        ]), patch.object(dt, 'get_findings', side_effect=lambda project: [newer['finding'] if project == 'rc5' else old['finding']]), patch.object(dt, 'read_analysis', return_value={**self.analysis, 'analysisComments': old['comments']}):
            audits = dt.find_previous_audits()
        self.assertEqual(len(audits), 2)
        with patch.object(dt, 'get_findings', return_value=[self.finding]), patch.object(dt, 'read_analysis', side_effect=[{}, self.analysis, self.analysis]), patch.object(dt, 'request', return_value=(200, b'{}')) as request:
            dt.carry_forward_audits('project', audits)
        payload = json.loads(request.call_args_list[0].kwargs['body'])
        self.assertIn('Copied from version rc.4', payload['comment'])

    def test_failed_write_and_unverified_write_fail_the_run(self):
        for status in (403, 200):
            with self.subTest(status=status), patch.object(dt, 'get_findings', return_value=[self.finding]), patch.object(dt, 'read_analysis', return_value={}), patch.object(dt, 'request', return_value=(status, b'{}')):
                with self.assertRaises(SystemExit):
                    dt.carry_forward_audits('project', self.audits)

    def test_findings_pagination_includes_suppressed_on_every_page(self):
        with patch.object(dt, 'get_json', side_effect=[[self.finding] * 100, [self.finding]]) as read:
            self.assertEqual(len(dt.get_findings('project')), 101)
        self.assertIn('suppressed=true&pageSize=100&pageNumber=1', read.call_args_list[0].args[0])
        self.assertIn('suppressed=true&pageSize=100&pageNumber=2', read.call_args_list[1].args[0])


if __name__ == '__main__':
    unittest.main()
