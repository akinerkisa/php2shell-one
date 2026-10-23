# Changelog

## 0.4.0 — 2026-10-22

- Renamed the unified product to PHP2Shell One and added the `php2shell-one` entrypoint.
- Added `php2shell one` as the single-command fast assessment report and `capabilities` as the readiness view.
- Preserved all v0.3 verification, hunting, audit, hardening and proof-readiness modules.

## 0.3.0 — 2026-10-22

- Expanded the unified defensive toolkit while preserving the `php2shell` and `patchproof` commands.
- Added a capability/readiness view; differential proof is explicitly not implemented yet.
- Restored dpkg manifest byte-integrity verification before `FIXED_RUNTIME` and added `INTEGRITY_MISMATCH`.
- Added real Linux `/proc` and dpkg integration checks for CI.
- Bounded repository traversal by all visited files and rejected oversized log lines.

## 0.2.0 — 2026-10-22

- Introduced multi-purpose `php2shell` CLI: status, verify, hunt, repo-audit, config-audit, webcheck, rules.
- Kept legacy `patchproof` CLI, Ubuntu USN thresholds and runtime evidence engine.
- Added offline HTML/JSON/SARIF/CSV output for heuristic modules, benign fixtures and patched-only lab.
- Added documentation, SOC/DevOps workflow, GitHub Actions and conservative rule templates.
- No exploit generation, mass scanning, automatic IOC ingestion or verified comprehensive WAF block is claimed.

## 0.1.0 — 2026-10-21

- Initial PatchProof, focused on upstream/Ubuntu package and worker evidence.
