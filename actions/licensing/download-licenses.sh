#!/usr/bin/env bash
set -euo pipefail

SBOM="${1:-sbom.spdx}"
OUT_DIR="LICENSES"
mkdir -p "$OUT_DIR"

have_jq() { command -v jq >/dev/null 2>&1; }

# --- Collect license IDs from SPDX JSON ---
extract_json_ids() {
  jq -r '
    [
      .packages[]? | (.licenseDeclared?, .licenseConcluded?, (.licenseInfoFromFiles[]?))
    , (.hasExtractedLicensingInfos[]?.licenseId?)
    ] | flatten | map(select(. != null)) | .[]
  ' "$SBOM"
}

# --- Collect license IDs from SPDX Tag:Value ---
# Looks at PackageLicenseDeclared:, PackageLicenseConcluded:, and LicenseID:
extract_tagvalue_ids() {
  # grab raw license expressions / IDs
  grep -E '^(PackageLicenseDeclared|PackageLicenseConcluded|LicenseID):' "$SBOM" \
  | sed -E 's/^[^:]+:[[:space:]]*//' 
}

# --- Normalize license expressions into tokens (licenses + exceptions) ---
normalize_to_ids() {
  # Input: lines of SPDX license *expressions* or bare IDs
  # Output: one SPDX id per line (license ids + exception ids)
  # - split on () and whitespace
  # - drop operators AND/OR
  # - keep "WITH" neighbor as an exception id
  awk '
    {
      gsub(/[()]/, " ");            # remove parentheses
      n = split($0, a, /[[:space:]]+/)
      for (i = 1; i <= n; i++) {
        tok = a[i]
        if (tok == "" || tok == "AND" || tok == "OR") continue
        if (tok == "WITH") {  # next token is an exception id
          if (i+1 <= n) print a[i+1]
          i++ ; continue
        }
        print tok
      }
    }
  ' | sed -E 's/[+]+//g'   # just in case of odd formatting
}

# --- Decide format (JSON vs Tag:Value) ---
if file --mime-type "$SBOM" | grep -q json; then
  RAW_IDS=$(extract_json_ids || true)
elif [[ "${SBOM##*.}" == "json" ]]; then
  RAW_IDS=$(extract_json_ids || true)
else
  # try to detect JSON by probing first char
  if head -c1 "$SBOM" | grep -q '{'; then
    RAW_IDS=$(extract_json_ids || true)
  else
    RAW_IDS=$(extract_tagvalue_ids || true)
  fi
fi

if [[ -z "${RAW_IDS:-}" ]]; then
  echo "No licenses found in $SBOM (or unsupported format)." >&2
  exit 1
fi

ALL_IDS=$(printf "%s\n" "$RAW_IDS" | normalize_to_ids | sort -u)

# Split into standard SPDX IDs vs LicenseRef...
STD_IDS=$(printf "%s\n" "$ALL_IDS" \
  | grep -Ev '^(LicenseRef|NONE|NOASSERTION)$' \
  | grep -Ev '^(AND|OR|WITH)$' \
  || true)

REF_IDS=$(printf "%s\n" "$ALL_IDS" \
  | grep -E '^LicenseRef' || true)

echo "==> Standard SPDX IDs to download:"
printf '  - %s\n' $STD_IDS 2>/dev/null || true

echo "==> LicenseRef IDs to create placeholders for:"
printf '  - %s\n' $REF_IDS 2>/dev/null || true

# --- Download standard licenses via REUSE ---
if ! command -v reuse >/dev/null 2>&1; then
  echo "Installing reuse..."
  python3 -m pip install --quiet --upgrade reuse
fi

# Download each ID (licenses and exceptions)
while read -r id; do
  [[ -z "$id" ]] && continue
  reuse download "$id" || {
    echo "Warning: could not download '$id' (not on SPDX list or network issue)" >&2
  }
done <<< "$STD_IDS"

# --- Create placeholders for LicenseRef… ---
while read -r ref; do
  [[ -z "$ref" ]] && continue
  f="$OUT_DIR/${ref}.txt"
  if [[ ! -f "$f" ]]; then
    cat > "$f" <<EOF
${ref}
This is a custom (non-SPDX) license referenced in the SBOM.
Provide the full text or a pointer to your proprietary license terms here.
EOF
    echo "Created $f"
  fi
done <<< "$REF_IDS"

echo "Done. License texts are in $OUT_DIR/"
