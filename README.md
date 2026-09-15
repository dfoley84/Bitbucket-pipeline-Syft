# Syft & Grype Security Scan — Bitbucket Pipe

A reusable Bitbucket Pipe that generates Software Bills of Materials (SBOMs) with
[Syft](https://github.com/anchore/syft) and scans for vulnerabilities with
[Grype](https://github.com/anchore/grype). Supports **Java** (including nested JARs),
**Python**, **Go**, and generic projects.

After each scan the pipe automatically posts a formatted vulnerability summary
as a comment on the pull request, including clickable [OSV.dev](https://osv.dev)
links and CVE descriptions.

---

## PR Comment

When running on a pull request the pipe posts (and updates on re-runs) a comment like:

> ## 🔍 Syft & Grype Security Scan
>
> 🟠 **1 high vulnerability found.**
>
> | Severity | Count |
> |----------|------:|
> | 🔴 Critical | 0 |
> | 🟠 High | 1 |
> | 🟡 Medium | 4 |
> | 🔵 Low | 0 |
> | ⚪ Negligible | 0 |
> | **Total** | **5** |
>
> | Package | CVE / GHSA | Severity | Fixed In | Description |
> |---------|-----------|----------|----------|-------------|
> | `requests@2.19.1` | [CVE-2018-18074](https://osv.dev/vulnerability/CVE-2018-18074) | 🟠 High | `2.20.0` | The Requests package before 2.20.0 sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect… |

Requires `BB_TOKEN` to be set as a repository variable. If not on a PR, the comment
step is skipped silently and the scan still completes.

---

## Usage

Add the pipe to any step in your `bitbucket-pipelines.yml`:

```yaml
- step:
    name: SBOM & Vulnerability Scan
    script:
      - pipe: docker://davefoley/bitbucket-syft:latest
        variables:
          SCAN_PATH: '.'              # optional, default: .
          LANGUAGE: 'auto'           # optional, default: auto
          FAIL_ON: 'critical'         # optional, default: critical
          ONLY_FIXED: 'true'          # optional, default: true
          SBOM_OUTPUT_DIR: '.'        # optional, default: .
          BB_TOKEN: $BB_TOKEN         # required for PR comments
    artifacts:
      - sbom.spdx.json
      - sbom.cyclonedx.json
      - sbom-summary.txt
      - nested-jars-scan.txt
      - vulnerability-report.json
      - grype-results.sarif
```

### Language Examples

**Java (Gradle / Maven)**
```yaml
- pipe: docker://davefoley/bitbucket-syft:latest
  variables:
    SCAN_PATH: 'build'
    LANGUAGE: 'java'
    FAIL_ON: 'critical'
    ONLY_FIXED: 'true'
    BB_TOKEN: $BB_TOKEN
```

**Python**

> **Note:** For Syft to detect Python dependencies the project must have a
> `requirements.txt` file. Syft does not resolve `pyproject.toml` dependencies
> without packages being installed. The simplest fix is to maintain a
> `requirements.txt` alongside `pyproject.toml`.

```yaml
- pipe: docker://davefoley/bitbucket-syft:latest
  variables:
    SCAN_PATH: '.'
    LANGUAGE: 'python'
    FAIL_ON: 'high'
    ONLY_FIXED: 'true'
    BB_TOKEN: $BB_TOKEN
```

**Go**
```yaml
- pipe: docker://davefoley/bitbucket-syft:latest
  variables:
    SCAN_PATH: '.'
    LANGUAGE: 'go'
    FAIL_ON: 'critical'
    BB_TOKEN: $BB_TOKEN
```

**Report-only (never fail the pipeline)**
```yaml
- pipe: docker://davefoley/bitbucket-syft:latest
  variables:
    FAIL_ON: 'none'
    BB_TOKEN: $BB_TOKEN
```

---

## Variables

| Variable          | Required | Default    | Description |
|-------------------|----------|------------|-------------|
| `SCAN_PATH`       | No       | `.`        | Path to scan. For Java, use your build output dir (e.g. `build` or `target`). |
| `LANGUAGE`        | No       | `auto`     | `auto`, `java`, `python`, `go`, or `generic`. `auto` detects from project files. |
| `FAIL_ON`         | No       | `critical` | Fail if vulnerabilities at this severity or above are found. Use `none` for report-only mode. |
| `ONLY_FIXED`      | No       | `true`     | When `true`, policy check only fails on vulnerabilities that have a known fix available. |
| `SBOM_OUTPUT_DIR` | No       | `.`        | Directory to write artifact files. |
| `DEBUG`           | No       | `false`    | Enable verbose debug output. |
| `BB_TOKEN`        | No*      | —          | Bitbucket access token. Required for PR comments; scan runs without it. |

---

## Artifacts

| File                        | Description |
|-----------------------------|-------------|
| `sbom.spdx.json`            | SPDX 2.x SBOM (JSON) |
| `sbom.cyclonedx.json`       | CycloneDX SBOM (JSON) |
| `sbom-summary.txt`          | Human-readable package table |
| `nested-jars-scan.txt`      | Per-JAR Syft analysis (Java only) |
| `vulnerability-report.json` | Full Grype results (JSON) |
| `grype-results.sarif`       | SARIF report for security tool integrations |

---

## Python — requirements.txt

Syft reads `requirements.txt` directly. It does **not** resolve `[project].dependencies`
from `pyproject.toml` without installed packages. Add a `requirements.txt` to your repo:

```
# requirements.txt
my-package==1.2.3
another-dep==4.5.6
```

---

## Execution Flow

```
pipe.py  (variable validation)
  ├── pipe.sh        — SBOM generation (Syft) + vulnerability scan (Grype) + policy check
  └── pr_comment.py  — post/update vulnerability summary on the PR (best-effort)
```

---

## Publishing the Pipe

1. Set repository variables in Bitbucket:
   - `DOCKERHUB_USERNAME` — your Docker Hub username or org
   - `DOCKERHUB_PASSWORD` — a Docker Hub access token (mark as **secret**)

2. Push to `main` to build and publish `latest` automatically.

3. Push a semver tag to publish a versioned release:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

4. To rebuild and push manually:
   ```bash
   docker build -t davefoley/bitbucket-syft:latest .
   docker push davefoley/bitbucket-syft:latest
   ```

---

## Project Structure

```
dockerfile                  # Docker image definition
pipe.yml                    # Pipe metadata and variable schema
pipe.py                     # Python entrypoint (variable validation)
pipe.sh                     # Main scan logic (Syft + Grype)
pr_comment.py               # Posts vulnerability summary as a PR comment
bitbucket-pipelines.yml     # CI/CD for building and publishing the pipe
pyproject.toml              # Python project metadata
requirements.txt            # Python dependencies (read by Syft)
```


---

## Usage

Add the pipe to any step in your `bitbucket-pipelines.yml`:

```yaml
- step:
    name: SBOM & Vulnerability Scan
    script:
      - pipe: docker://your-dockerhub-org/syft-grype-pipe:latest
        variables:
          SCAN_PATH: 'build'          # optional, default: .
          LANGUAGE: 'java'            # optional, default: auto
          FAIL_ON: 'critical'         # optional, default: critical
          ONLY_FIXED: 'true'          # optional, default: true
          SBOM_OUTPUT_DIR: '.'        # optional, default: .
    artifacts:
      - sbom.spdx.json
      - sbom.cyclonedx.json
      - sbom-summary.txt
      - nested-jars-scan.txt
      - vulnerability-report.json
      - grype-results.sarif
```

### Language Examples

**Java (Gradle / Maven)**
```yaml
- pipe: docker://your-dockerhub-org/syft-grype-pipe:latest
  variables:
    SCAN_PATH: 'build'
    LANGUAGE: 'java'
    FAIL_ON: 'critical'
    ONLY_FIXED: 'true'
```

**Python**
```yaml
- pipe: docker://your-dockerhub-org/syft-grype-pipe:latest
  variables:
    SCAN_PATH: '.'
    LANGUAGE: 'python'
    FAIL_ON: 'high'
    ONLY_FIXED: 'false'
```

**Go**
```yaml
- pipe: docker://your-dockerhub-org/syft-grype-pipe:latest
  variables:
    SCAN_PATH: '.'
    LANGUAGE: 'go'
    FAIL_ON: 'critical'
```

**Report-only (never fail the pipeline)**
```yaml
- pipe: docker://your-dockerhub-org/syft-grype-pipe:latest
  variables:
    FAIL_ON: 'none'
```

---

## Variables

| Variable         | Required | Default      | Description |
|------------------|----------|--------------|-------------|
| `SCAN_PATH`      | No       | `.`          | Path to scan. For Java, use your build output dir (e.g. `build` or `target`). |
| `LANGUAGE`       | No       | `auto`       | `auto`, `java`, `python`, `go`, or `generic`. `auto` detects from project files. |
| `FAIL_ON`        | No       | `critical`   | Fail if vulnerabilities at this severity or above are found. Use `none` for report-only. |
| `ONLY_FIXED`     | No       | `true`       | When `true`, policy check only fails on vulnerabilities that have a known fix. |
| `SBOM_OUTPUT_DIR`| No       | `.`          | Directory to write artifact files. |
| `DEBUG`          | No       | `false`      | Enable verbose debug output. |

---

## Artifacts

| File                      | Description |
|---------------------------|-------------|
| `sbom.spdx.json`          | SPDX 2.x SBOM (JSON) |
| `sbom.cyclonedx.json`     | CycloneDX SBOM (JSON) |
| `sbom-summary.txt`        | Human-readable package table |
| `nested-jars-scan.txt`    | Per-JAR Syft analysis (Java only) |
| `vulnerability-report.json` | Full Grype results (JSON) |
| `grype-results.sarif`     | SARIF report for security tool integrations |

---

## Publishing the Pipe

1. Set repository variables in Bitbucket:
   - `DOCKERHUB_USERNAME` — your Docker Hub username or org
   - `DOCKERHUB_PASSWORD` — a Docker Hub access token (mark as **secret**)

2. Push to `main` to publish `latest` automatically.

3. Push a tag (`v1.0.0`) to publish a versioned release:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

---

## Project Structure

```
dockerfile                  # Docker image definition
pipe.yml                    # Pipe metadata and variable schema
pipe.py                     # Python entrypoint (variable validation)
pipe.sh                     # Main scan logic (Syft + Grype)
bitbucket-pipelines.yml     # CI/CD for building and publishing the pipe
pyproject.toml              # Python project metadata
```
