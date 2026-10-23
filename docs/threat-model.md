# Security model

**Scope:** Defensive post-disclosure response to the PHP interpreter memory-safety CVEs. We separate five evidence classes:

1. **Advisory** — PHP or vendor-published fixed version threshold, with source.
2. **Package** — installed version meets applicable signed-vendor distribution threshold; apt-index provenance is only corroboration, not cryptographic attestation.
3. **Runtime** — running FPM/mod_php worker shows a current mapped package-owned binary (Linux-specific).
4. **Traffic** — access/error log events consistent with suspicious patterns; inherently circumstantial.
5. **Outcome** — process/EDR findings that may support investigation; still not proof that one of these CVEs caused it.

**Trust boundaries:** Logs, filenames, HTTP headers, JSONL and repository files are untrusted input. No user-controlled string is passed to a shell. The CLI reads local files with bounded per-file lines and supports sensitive-data-minimizing output. The optional `webcheck --authorized` contacts one explicit URL via HEAD and forbids redirects. Docker image inspection is inherited from PatchProof: create stopped container, copy filesystem evidence, remove container. Docker itself has high privileges; only run on a trusted machine/image.

**False assurance risk:** We never infer `PATCHED` from missing alerts. `UNKNOWN` is preferable to a false negative. WAF mitigations are incomplete and deployment-specific. Memory-limit reconfiguration can cause DoS side effects. Scan/review results must not be promoted to a vulnerability absence statement.

**Sensitive data:** Session cookies, upload bodies and raw URL query strings are intentionally omitted. Client IPs are pseudonymized by default using truncated SHA-256, not irreversibly anonymized against a small IP candidate set; prefer handling data as sensitive. Source file paths, IOC hash values and path segments may be exposed in reports.

**No exploit or payloads:** This repository never sends multipart attack requests, OOM stress payloads, or RCE commands. `lab` is patched and uses normal GET smoke checks. No automatic network crawling or mass scanning is provided.
