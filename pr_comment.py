"""
Post Syft & Grype vulnerability findings as a summary comment on a Bitbucket PR.

Reads vulnerability-report.json produced by the Syft & Grype pipe and posts
a formatted markdown table on the current pull request. Any previous scan
comment is deleted first to avoid duplicates.
"""

import json
import os
import sys

import requests

COMMENT_MARKER = "<!-- syft-grype-scan-report -->"

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible"]
SEVERITY_EMOJI = {
    "Critical":   "🔴",
    "High":       "🟠",
    "Medium":     "🟡",
    "Low":        "🔵",
    "Negligible": "⚪",
}

# ─── Guard checks ─────────────────────────────────────────────────────────────
PR_ID = os.environ.get("BITBUCKET_PR_ID")
if not PR_ID:
    print("PR comment | BITBUCKET_PR_ID not set — not running on a PR, skipping.")
    sys.exit(0)

REPORT_FILE = os.environ.get("VULN_REPORT", "vulnerability-report.json")
if not os.path.exists(REPORT_FILE):
    print(f"PR comment | {REPORT_FILE} not found — skipping.")
    sys.exit(0)

WORKSPACE = os.environ.get("BITBUCKET_WORKSPACE")
REPO_SLUG = os.environ.get("BITBUCKET_REPO_SLUG")
TOKEN     = os.environ.get("BB_TOKEN")

if not WORKSPACE or not REPO_SLUG:
    print("PR comment | BITBUCKET_WORKSPACE or BITBUCKET_REPO_SLUG not set — skipping.")
    sys.exit(0)

if not TOKEN:
    print("PR comment | BB_TOKEN not set — skipping. Set it as a repository variable.")
    sys.exit(0)

print(f"PR comment | Posting to PR #{PR_ID} in {WORKSPACE}/{REPO_SLUG}")
print(f"PR comment | Reading report: {REPORT_FILE}")

API_BASE = (
    f"https://api.bitbucket.org/2.0/repositories"
    f"/{WORKSPACE}/{REPO_SLUG}/pullrequests/{PR_ID}"
)
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
}

# ─── Load report ─────────────────────────────────────────────────────────────
with open(REPORT_FILE) as f:
    data = json.load(f)

matches = data.get("matches", [])

# ─── Count by severity ────────────────────────────────────────────────────────
counts = {s: 0 for s in SEVERITY_ORDER}
for match in matches:
    sev = match.get("vulnerability", {}).get("severity", "Negligible")
    if sev in counts:
        counts[sev] += 1

total = sum(counts.values())

# ─── Build per-package vulnerability table ───────────────────────────────────
sev_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}

pkg_vulns: dict[str, list[dict]] = {}
for match in matches:
    vuln     = match.get("vulnerability", {})
    artifact = match.get("artifact", {})
    key      = f"{artifact.get('name')}@{artifact.get('version')}"
    raw_desc = vuln.get("description", "").strip()
    short_desc = (raw_desc[:120] + "…") if len(raw_desc) > 120 else raw_desc
    pkg_vulns.setdefault(key, []).append({
        "id":          vuln.get("id", "unknown"),
        "severity":    vuln.get("severity", "Unknown"),
        "fixed_in":    ", ".join(vuln.get("fix", {}).get("versions", [])) or "—",
        "description": short_desc,
    })

# Sort packages: worst severity first
top_packages = sorted(
    pkg_vulns.items(),
    key=lambda x: min(sev_rank.get(v["severity"], 99) for v in x[1]),
)[:20]

# ─── Status headline ─────────────────────────────────────────────────────────
if total == 0:
    headline = "✅ **No vulnerabilities found.**"
elif counts["Critical"] > 0:
    n = counts["Critical"]
    headline = f"🔴 **{n} critical vulnerabilit{'y' if n == 1 else 'ies'} found — immediate action required.**"
elif counts["High"] > 0:
    n = counts["High"]
    headline = f"🟠 **{n} high vulnerabilit{'y' if n == 1 else 'ies'} found.**"
else:
    headline = f"🟡 **{total} vulnerabilit{'y' if total == 1 else 'ies'} found (no critical/high).**"

# ─── Build comment body ──────────────────────────────────────────────────────
lines = [
    COMMENT_MARKER,
    "## 🔍 Syft & Grype Security Scan",
    "",
    headline,
    "",
    "### Vulnerability Summary",
    "",
    "| Severity | Count |",
    "|----------|------:|",
]

for sev in SEVERITY_ORDER:
    lines.append(f"| {SEVERITY_EMOJI[sev]} {sev} | {counts[sev]} |")

lines += [
    f"| **Total** | **{total}** |",
    "",
]

if top_packages:
    lines += [
        "### Vulnerable Packages",
        "",
        "| Package | CVE / GHSA | Severity | Fixed In | Description |",
        "|---------|-----------|----------|----------|-------------|",
    ]
    for pkg, vulns in top_packages:
        for v in sorted(vulns, key=lambda x: sev_rank.get(x["severity"], 99)):
            emoji = SEVERITY_EMOJI.get(v["severity"], "")
            vuln_url = f"https://osv.dev/vulnerability/{v['id']}"
            lines.append(
                f"| `{pkg}` | [{v['id']}]({vuln_url}) | {emoji} {v['severity']} | `{v['fixed_in']}` | {v['description']} |"
            )
    lines.append("")

lines += [
    "<details>",
    "<summary>Scan details</summary>",
    "",
    f"- **Report:** `{REPORT_FILE}`",
    f"- **Total matches:** {len(matches)}",
    f"- **Unique packages affected:** {len(pkg_vulns)}",
    "",
    "</details>",
]

body = "\n".join(lines)

# ─── Remove previous scan comment(s) ─────────────────────────────────────────
url = f"{API_BASE}/comments?pagelen=100"
while url:
    existing = requests.get(url, headers=HEADERS)
    existing.raise_for_status()
    page = existing.json()
    for comment in page.get("values", []):
        if COMMENT_MARKER in comment.get("content", {}).get("raw", ""):
            cid = comment["id"]
            resp = requests.delete(f"{API_BASE}/comments/{cid}", headers=HEADERS)
            if resp.status_code == 204:
                print(f"Removed previous scan comment #{cid}")
    url = page.get("next")

# ─── Post new comment ────────────────────────────────────────────────────────
if total == 0:
    print("PR comment | No vulnerabilities found — skipping comment.")
    sys.exit(0)

resp = requests.post(
    f"{API_BASE}/comments",
    headers=HEADERS,
    json={"content": {"raw": body}},
)

if resp.status_code >= 300:
    print(f"Failed to post comment: {resp.status_code} {resp.text}")
    sys.exit(1)

print(f"Posted vulnerability summary on PR #{PR_ID}")
for sev in SEVERITY_ORDER:
    if counts[sev]:
        print(f"  {SEVERITY_EMOJI[sev]} {sev}: {counts[sev]}")