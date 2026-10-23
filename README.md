# PHP2Shell One

**Run locally. Check your PHP2Shell exposure. Generate an evidence-based security report.**

**One focused toolkit for CVE-2026-109618 & CVE-2026-109619: verify, hunt, audit, harden and track differential-proof readiness.**

**Inventory PHP. Verify patch provenance. Hunt your logs. Review Dockerfiles. Inspect PHP configurations. Produce reports. Deploy conservative defense-in-depth templates.** All in one open-source repository, using Python's standard library.

> **Read this first:** This project does not generate exploit payloads, does not fuzz PHP memory safety, and does not claim an HTTP header or WAF can prove a system patched. The *only complete remedy* is a patched PHP runtime (or vendor-confirmed backport), deployed to **all running workers**. Detection rules are heuristics. All sample traffic is benign.

## Quick start — works on Linux, macOS and Windows for offline commands

Python **3.10+** is required. No third-party runtime Python dependencies.

```bash
# In the repository root:
python -m pip install .
php2shell --help
php2shell status
php2shell one --format html --output php2shell-one-report.html

# One-command, multi-source offline HTML assessment
php2shell assess --repo . --access-log examples/access.log --config examples/php.ini \
  --format html --output assessment.html

# Try a fully offline hunt on included synthetic logs
php2shell hunt --access-log examples/access.log \
  --error-log examples/error.log --events-json examples/events.jsonl

# Inspect Dockerfile/Compose image pins (no build/pull)
php2shell repo-audit ./lab

# Generate a local HTML report
php2shell hunt --access-log examples/access.log --format html --output report.html
```

For a zero-install, read-only inventory on a machine that already has PHP CLI:

```bash
php php2shell-one.php
php php2shell-one.php --json
```

The single-file collector makes no network requests and does not attempt an
exploit. It reports only the PHP CLI runtime that executes it; CLI settings can
differ from PHP-FPM or Apache. It deliberately does not produce a patched or
vulnerable verdict. Web execution is denied by default.

**Windows PowerShell:** use the same `php2shell` command; separate lines with PowerShell backticks or put arguments on one line. If the console entrypoint is not on `PATH`, use `python -m php2shellkit.cli`.

## Choose a workflow

`php2shell one` is the fast path: it audits the selected repository, checks a
small documented set of local PHP config/log filenames, and automatically adds
read-only runtime inventory on Linux. It performs no recursive log discovery or
network requests. **It is not a complete filesystem or environment scan, and a
report with no findings does not mean the host or application is safe.** Pass
additional files explicitly or use the dedicated commands for deeper review.
Use `php2shell-one capabilities` for the capability manifest. It deliberately
reports `differential-proof` as `not-implemented` until pinned
vulnerable and patched builds, an identical bounded regression input, and a
negative control exist. Inventory or a patched-only smoke test is never labeled a PoC.

| Who | Task | Command | Important limit |
| --- | --- | --- | --- |
| Team lead / mixed environment | Combined offline triage report | `php2shell assess --repo . --access-log access.log --config php.ini --format html` | Aggregated indicators are not proof of exploitability |
| Server administrator | Review installed Ubuntu PHP packages and observed FPM/mod_php workers | `php2shell verify --local --strict` | Needs Linux; /proc may require privileges; unknown is not safe |
| DevOps/SRE | Audit a stopped local Docker image | `php2shell verify --docker-image php:8.3.36-fpm` | Docker daemon required; does **not** start image or attest running process |
| Image/SBOM owner | Examine mounted root filesystem | `php2shell verify --rootfs /mnt/image --format json` | No package provenance or live process proof |
| Developer/AppSec | Review Dockerfiles and Compose tags | `php2shell repo-audit . --format sarif --output results.sarif` | Static tags can lie; only official `php:*` image references evaluated |
| PHP operator | Inspect php.ini / FPM pool | `php2shell config-audit /etc/php/8.3/fpm/php.ini` | Settings may be overridden; config is **not** a patch |
| SOC analyst | Hunt Apache/Nginx access, PHP error and EDR JSONL logs | `php2shell hunt --access-log access.log --error-log error.log --events-json events.jsonl` | Heuristic signals, no compromise determination |
| DFIR analyst | Add independently curated IOC data | `php2shell hunt --access-log access.log --ioc-file iocs.json` | Exact IP/hash observations only; not attribution |
| WAF operator | Review safe baseline templates | `php2shell rules list` | Not tested as comprehensive PHP2Shell blockers |
| Asset owner | One benign HTTP HEAD on a site they control | `php2shell webcheck https://example.org/ --authorized` | **Never** used as a vulnerability verdict |
| CI team | Fail build on obviously old official PHP Docker tags | `php2shell repo-audit . --fail-on high` | Does not inspect deployed image |

### Example outputs

```text
$ php2shell repo-audit ./lab
PHP2Shell One | repo-audit
Findings: 1 (high 0, medium 0, low 0, info 1)
[INFO] PHP_TAG_FIXED_CLAIM docker-compose.yml:4 — PHP image tag 8.3.36-cli meets upstream threshold;
  tag alone does not prove deployed runtime safety
```

```
$ php2shell verify --version 8.3.35
... CLI: PHP 8.3.35 (BELOW_FIXED_VERSION)
... Overall runtime: UNKNOWN
```

Both examples are **version/tag observations**, not proofs of exploitation or safety.

## Advisory-backed fixed versions

PHP Security Team's 21 October 2026 releases:

| PHP branch | First fixed version |
| --- | --- |
| 8.2 | **8.2.35** |
| 8.3 | **8.3.36** |
| 8.4 | **8.4.27** |
| 8.5 | **8.5.12** |

PHP2Shell includes **CVE-2026-109618** (OOM corruption) and **CVE-2026-109619** (stale request-global state / UAF). Both may permit unauthenticated remote code execution. PHP's official notice warns that **there is no complete mitigation other than updating**.

Canonical Ubuntu **USN-8948-1** and **USN-8948-2** publish security-backported package minimums, including PHP 8.1 and older releases. A vendor-fixed PHP 8.3.6 package need not report PHP 8.3.36. Conversely an upstream version string alone does not prove a running worker has loaded patched bytes. Dataset is **pinned to 2026-10-21**, not an automatically maintained universal advisory database.

Supported upstream branches: 8.2–8.5. Ubuntu policy: 14.04, 16.04, 18.04, 20.04, 22.04, 24.04, 26.04, 26.10. Older Ubuntu versions may require ESM/Pro or other subscription support. All other vendor ecosystems remain `UNKNOWN` unless confirmed separately.

## Commands and examples

### 0. Unified assessment

`php2shell assess` merges any combination of a source repository, PHP config files and local logs into one evidence report. Add `--local` on Linux for a *summary* of worker evidence (full provenance remains in `verify --local`). No remote requests are sent. This is the simplest workflow for most teams.

### 1. Local patch verification

```bash
php2shell verify --local --format json --output php-evidence.json
php2shell verify --local --strict
php2shell verify --version 8.4.26
php2shell verify --rootfs /path/to/extracted-rootfs
php2shell verify --docker-image local-php-image:tag
```

PatchProof evaluates upstream thresholds, Ubuntu dpkg status and official APT index origin where available, binary ownership, and observable loaded FPM/mod_php processes. It refuses to emit a patched runtime conclusion without adequate evidence. An offline image cannot have its running worker verified. The legacy `patchproof` executable remains available (`patchproof --help`).

**Strict exit codes for `verify`:** `0` = verified observed runtime fixed; `2` = observed at-risk or restart required; `3` = unknown; `1` = error. Without `--strict`, a completed report exits `0` regardless of findings. **Version-only mode always exits `3` in strict mode**, even if its version meets the threshold.

### 2. Offline hunt

```bash
php2shell hunt --access-log /var/log/nginx/access.log --error-log /var/log/php8.3-fpm.log
php2shell hunt --access-log access.log.1.gz --since 2026-10-17T00:00:00Z
php2shell hunt --events-json ./edr.jsonl --ioc-file ./approved-iocs.json --format json --output findings.json
php2shell hunt --access-log access.log --show-ips  # opt-in cleartext client IPs
```

Inputs: Apache combined logs and common Nginx JSON access logs, plaintext or `.gz`; PHP error logs; simple EDR JSONL (e.g. `{"process":{"name":"sh","parent":{"name":"php-fpm8.3"}}}`). IOC file: JSON object `{"ips":["192.0.2.20"],"sha256":["64 hex characters..."]}`. **No external IOC feed is fetched automatically.**

Findings: IOC matches, visible session-progress markers, scanner canaries, repeated POST 5xx on one path, PHP OOM diagnostics, worker crashes, and unexpected child process telemetry. These are investigation leads, **not proof of exploitation**. Normal access logs usually omit multipart bodies; a clean report **does not** establish no attack occurred. `--since` reliably filters only records with parsed timestamps; error-log timestamps are not parsed in this version.

Default reports replace client IPs with deterministic short SHA-256 aliases and never export raw request strings, query parameters, cookies, or POST bodies. Sensitive filenames/URI paths and submitted IOC hash values might remain; treat exported reports as sensitive. `--max-lines` caps input processing per file.

### 3. Source repository review

```bash
php2shell repo-audit .
php2shell repo-audit . --format sarif --output php2shell.sarif --fail-on high
```

Finds official `php:*` image references in Dockerfiles and Compose files. Clear pre-fix patch tags trigger high-severity **version pin** findings; floating, templated and digest references result in informational or uncertain outcomes. It does not inspect PHP installed inside arbitrary base images, build ARG expansion, registry signatures or deployed container digests.

### 4. Configuration and firewall baseline

```bash
php2shell config-audit /etc/php/8.3/fpm/php.ini /etc/php/8.3/fpm/pool.d/www.conf
php2shell rules list
php2shell rules show modsecurity/request-limits.conf
php2shell rules show modsecurity/no-multipart.example.conf
php2shell rules show nginx/request-limits.conf
```

ModSecurity and Nginx snippets are **review templates**. Request-size limits reduce some exposure but cannot account for every multipart parser failure path. The opt-in multipart blocking rule is **only** for upload-free endpoints. Some knobs such as `memory_limit=-1` change OOM behavior but can increase overall DoS risk. Never apply an unreviewed snippet globally or claim a rule patches PHP.

### 5. Explicitly authorized metadata-only web check

```bash
php2shell webcheck https://your-authorized-host.example/ --authorized --format json
```

Sends **one HTTPS HEAD request**, follows no redirects, sends no exploit, POST or form. An `X-Powered-By` version is untrusted informational evidence; proxy, headers and application spoofing make remote patch status impossible to establish from this method.

### 6. Reports and continuous integration

- `assess`, `hunt`, `repo-audit`, `config-audit`, `webcheck`: `--format text|json|csv|sarif|html`.
- `verify`: `--format text|json|sarif` (PatchProof evidence schema).
- `--fail-on high` or `--fail-on medium` for heuristic modules returns `2` when threshold is met; default is non-failing reporting.
- `.github/workflows/tests.yml` runs the unit suite on Python 3.10–3.13 and CLI smoke checks.
- `.github/workflows/repo-audit.yml` reviews Dockerfile/Compose pins on pull requests, with SARIF artifact upload.

`html` is **single-file, completely offline, no external JavaScript or CSS**. Open locally in a browser. It is escaped before rendering untrusted input. Do not publish sensitive reports.

## Directory layout

```text
src/
  php2shellkit/         # CLI, hunting, repository/config/metadata review, rendering
  patchproof/           # Preserved rigorous local/version/vendor verification engine
rules/                  # ModSecurity, Nginx, experimental Sigma
lab/                    # Patched-only, localhost-bound, non-exploit smoke test
examples/               # Synthetic access/error/EDR logs and optional IOC schema
tests/                  # Offline unittest suite
docs/                   # Operational guides, limitations, source provenance
.github/workflows/      # Automated tests and static repository review
```

## Trust and limitations

- **Not a general unauthenticated vulnerability scanner.** There is no exploit-based proof of RCE or patch.
- **Not universal vendor coverage.** Non-Ubuntu vendor backports are unknown by default; see [coverage](docs/coverage.md).
- **Not an automatic incident-response verdict.** Heuristics require a trained responder to correlate request, response, runtime and EDR evidence.
- **Not automatically updated threat intelligence.** Use a curated, verified IOC file and record its source; do not treat raw IP matches as attribution.
- **No live sample execution.** The [lab](lab/README.md) serves one benign endpoint on a patched PHP tag. The repository ships no exploit or memory-stress harness.
- **Read permissions matter.** Host process checks may be incomplete due to `/proc` visibility, container isolation or user permissions.
- **Review before production.** WAF snippets and Sigma YAML have not been integration-tested against all vendor engines.

## Responsible use and disclaimer

Use this project only on systems you own or are explicitly authorized to
assess. You are responsible for complying with applicable laws, agreements and
organizational policies. The maintainers do not endorse unauthorized testing or
use of this project to disrupt systems.

Reports are investigative aids, not guarantees of security, compromise,
exploitability or patch status, and they are not legal advice. Review findings
and remediation with qualified personnel before making production decisions.
This software is provided "as is", without warranty; see the [MIT License](LICENSE)
for the complete warranty and liability terms.

See [threat model](docs/threat-model.md), [incident response runbook](docs/incident-response.md), [architecture](docs/architecture.md), [coverage](docs/coverage.md), [sources](docs/sources.md), [security policy](SECURITY.md) and [contributing](CONTRIBUTING.md).

## Official sources

- [PHP Security Advisory, 21 October 2026](https://www.php.net/archive/2026.php#2026-10-21-5)
- [GHSA-w8hw-w9fx-j79w: OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp: stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Canonical USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1) and [USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2)
- [php-src fixed code changes](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065)
- [Cloudflare attack telemetry and WAF context](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/)
- [Elastic post-exploitation detection rationale](https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection)

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python -m compileall -q src
```

Python standard library at runtime. MIT license. Contributions are welcome, particularly **officially sourced, tested vendor-specific support**, log parsers and defensive tests that do not contain exploit payloads.
