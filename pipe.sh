#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Bitbucket Pipe: Syft & Grype Security Scan
# Generates SBOMs with Syft and scans for vulnerabilities with Grype.
# Supports Java (including nested JARs), Python, Go, and generic projects.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ─── Variables (injected by pipe.py) ─────────────────────────────────────────
SCAN_PATH="${SCAN_PATH:-.}"
LANGUAGE="${LANGUAGE:-auto}"
FAIL_ON="${FAIL_ON:-critical}"
ONLY_FIXED="${ONLY_FIXED:-true}"
SBOM_OUTPUT_DIR="${SBOM_OUTPUT_DIR:-.}"
DEBUG="${DEBUG:-false}"

[[ "${DEBUG}" == "true" ]] && set -x

# ─── Logging helpers ─────────────────────────────────────────────────────────
info()    { echo "INFO  | $*"; }
warn()    { echo "WARN  | $*"; }
error()   { echo "ERROR | $*" >&2; }
divider() { echo "─────────────────────────────────────────────────────"; }

# ─── Language auto-detection ─────────────────────────────────────────────────
detect_language() {
  local path="$1"

  # Go
  if [[ -f "${path}/go.mod" ]] || [[ -f "${path}/go.sum" ]]; then
    echo "go"; return
  fi

  # Python
  if [[ -f "${path}/requirements.txt" ]] || \
     [[ -f "${path}/pyproject.toml" ]]   || \
     [[ -f "${path}/setup.py" ]]         || \
     [[ -f "${path}/Pipfile" ]]          || \
     [[ -f "${path}/poetry.lock" ]]; then
    echo "python"; return
  fi

  # Java
  if [[ -f "${path}/pom.xml" ]]         || \
     [[ -f "${path}/build.gradle" ]]     || \
     [[ -f "${path}/build.gradle.kts" ]] || \
     find "${path}" -maxdepth 3 -name "*.jar" -type f -quit 2>/dev/null; then
    echo "java"; return
  fi

  echo "generic"
}

# ─── Setup ───────────────────────────────────────────────────────────────────
mkdir -p "${SBOM_OUTPUT_DIR}"

SBOM_SPDX="${SBOM_OUTPUT_DIR}/sbom.spdx.json"
SBOM_CDX="${SBOM_OUTPUT_DIR}/sbom.cyclonedx.json"
SBOM_TXT="${SBOM_OUTPUT_DIR}/sbom-summary.txt"
VULN_JSON="${SBOM_OUTPUT_DIR}/vulnerability-report.json"
VULN_SARIF="${SBOM_OUTPUT_DIR}/grype-results.sarif"
JAR_SCAN="${SBOM_OUTPUT_DIR}/nested-jars-scan.txt"

if [[ "${LANGUAGE}" == "auto" ]]; then
  LANGUAGE=$(detect_language "${SCAN_PATH}")
  info "Auto-detected language: ${LANGUAGE}"
fi

divider
info "Syft & Grype Security Scan"
divider
info "Scan path:      ${SCAN_PATH}"
info "Language:       ${LANGUAGE}"
info "Fail on:        ${FAIL_ON}"
info "Only fixed:     ${ONLY_FIXED}"
info "Output dir:     ${SBOM_OUTPUT_DIR}"
divider

# ─── SBOM Generation ─────────────────────────────────────────────────────────
info "Generating SBOM for '${SCAN_PATH}' ..."

syft "dir:${SCAN_PATH}" \
  --output "spdx-json=${SBOM_SPDX}" \
  --output "cyclonedx-json=${SBOM_CDX}" \
  --output "table=${SBOM_TXT}"

# Package summary
PACKAGE_COUNT=$(jq '.packages | length' "${SBOM_SPDX}" 2>/dev/null || echo "0")
info "Total packages found: ${PACKAGE_COUNT}"

info "Package types breakdown:"
jq -r '.packages[] | .packageType // .type // "unknown"' "${SBOM_SPDX}" 2>/dev/null \
  | sort | uniq -c | sort -rn \
  || true

# ─── Language-specific Deep Scan ─────────────────────────────────────────────
case "${LANGUAGE}" in

  java)
    divider
    info "Java JAR Deep Scan"
    divider
    touch "${JAR_SCAN}"
    JAR_FOUND=false

    while IFS= read -r -d '' jar; do
      JAR_FOUND=true
      echo "Analyzing: ${jar}" | tee -a "${JAR_SCAN}"
      syft "${jar}" --output table 2>&1 | tee -a "${JAR_SCAN}"
      echo "---" | tee -a "${JAR_SCAN}"
    done < <(find "${SCAN_PATH}" -type f -name "*.jar" -print0 2>/dev/null)

    if [[ "${JAR_FOUND}" == "false" ]]; then
      warn "No JAR files found under '${SCAN_PATH}'"
      echo "No JAR files found under ${SCAN_PATH}" >> "${JAR_SCAN}"
    fi
    ;;

  python)
    divider
    info "Python Dependency Scan"
    divider
    # Syft's directory scan already handles pip/poetry/pipenv/uv.
    # Additionally surface any virtual environments.
    VENV_FOUND=false
    while IFS= read -r -d '' cfg; do
      venv_dir=$(dirname "${cfg}")
      VENV_FOUND=true
      info "Scanning virtual environment: ${venv_dir}"
      syft "dir:${venv_dir}" --output table 2>&1 || true
    done < <(find "${SCAN_PATH}" -name "pyvenv.cfg" -print0 2>/dev/null)

    if [[ "${VENV_FOUND}" == "false" ]]; then
      info "No virtual environments found — relying on project-level SBOM."
    fi
    ;;

  go)
    divider
    info "Go Module Scan"
    divider
    # Syft handles go.mod/go.sum natively in the directory scan.
    if [[ -f "${SCAN_PATH}/go.sum" ]]; then
      GO_ENTRIES=$(grep -c '.' "${SCAN_PATH}/go.sum" || echo "0")
      info "go.sum module entries: ${GO_ENTRIES}"
    fi
    if [[ -f "${SCAN_PATH}/go.mod" ]]; then
      info "go.mod module:"
      head -3 "${SCAN_PATH}/go.mod" || true
    fi
    ;;

  generic)
    info "Generic directory scan — no language-specific deep analysis."
    ;;

esac

divider
info "SBOM Summary"
divider
cat "${SBOM_TXT}" || true

# ─── Vulnerability Scanning ──────────────────────────────────────────────────
divider
info "Vulnerability Scanning with Grype"
divider

grype "sbom:${SBOM_SPDX}" \
  --output table \
  --by-cve \
  --output "json=${VULN_JSON}" \
  --output "sarif=${VULN_SARIF}" \
  || true   # allow non-zero; policy check is separate below

# ─── Vulnerability Summary ───────────────────────────────────────────────────
if [[ -f "${VULN_JSON}" ]]; then
  CRITICAL=$(jq '[.matches[] | select(.vulnerability.severity=="Critical")]   | length' "${VULN_JSON}" 2>/dev/null || echo 0)
  HIGH=$(jq     '[.matches[] | select(.vulnerability.severity=="High")]       | length' "${VULN_JSON}" 2>/dev/null || echo 0)
  MEDIUM=$(jq   '[.matches[] | select(.vulnerability.severity=="Medium")]     | length' "${VULN_JSON}" 2>/dev/null || echo 0)
  LOW=$(jq      '[.matches[] | select(.vulnerability.severity=="Low")]        | length' "${VULN_JSON}" 2>/dev/null || echo 0)
  NEGL=$(jq     '[.matches[] | select(.vulnerability.severity=="Negligible")] | length' "${VULN_JSON}" 2>/dev/null || echo 0)
  TOTAL=$(( CRITICAL + HIGH + MEDIUM + LOW + NEGL ))

  echo ""
  echo "╔══════════════════════════════════════╗"
  echo "║       VULNERABILITY SUMMARY          ║"
  echo "╠══════════════════════════════════════╣"
  printf  "║  %-12s %23s ║\n" "Critical:"   "${CRITICAL}"
  printf  "║  %-12s %23s ║\n" "High:"       "${HIGH}"
  printf  "║  %-12s %23s ║\n" "Medium:"     "${MEDIUM}"
  printf  "║  %-12s %23s ║\n" "Low:"        "${LOW}"
  printf  "║  %-12s %23s ║\n" "Negligible:" "${NEGL}"
  echo "╠══════════════════════════════════════╣"
  printf  "║  %-12s %23s ║\n" "Total:"      "${TOTAL}"
  echo "╚══════════════════════════════════════╝"

  if (( CRITICAL > 0 )); then
    echo ""
    divider
    info "Critical Vulnerability Details"
    divider
    jq -r '.matches[]
      | select(.vulnerability.severity=="Critical")
      | "\(.artifact.name)@\(.artifact.version)  →  \(.vulnerability.id)"' \
      "${VULN_JSON}" | sort -u
  fi

  echo ""
  divider
  info "Top 20 Vulnerable Packages"
  divider
  jq -r '.matches[] | "\(.vulnerability.severity)  \(.artifact.name)@\(.artifact.version)"' \
    "${VULN_JSON}" \
    | sort | uniq -c | sort -rn | head -20 \
    || true
else
  warn "vulnerability-report.json not found — Grype may have failed silently."
fi

# ─── Policy Check ────────────────────────────────────────────────────────────
echo ""
divider
if [[ "${FAIL_ON}" == "none" ]]; then
  info "Policy check skipped (FAIL_ON=none — report-only mode)."
else
  info "Policy Check  (fail-on: ${FAIL_ON}, only-fixed: ${ONLY_FIXED})"
  divider

  GRYPE_ARGS=("sbom:${SBOM_SPDX}" "--fail-on" "${FAIL_ON}")
  [[ "${ONLY_FIXED}" == "true" ]] && GRYPE_ARGS+=("--only-fixed")

  if grype "${GRYPE_ARGS[@]}"; then
    info "Policy check passed."
  else
    error "Policy check FAILED — ${FAIL_ON}+ severity vulnerabilities detected$(
      [[ "${ONLY_FIXED}" == "true" ]] && echo " (with available fixes)"
    )."
    exit 1
  fi
fi

divider
info "Scan complete. Artifacts written to: ${SBOM_OUTPUT_DIR}"
divider
