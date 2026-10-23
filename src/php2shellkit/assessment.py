"""Unified offline assessment, combining evidence without asserting RCE or immunity."""
from __future__ import annotations

from pathlib import Path
from .common import envelope
from .configcheck import inspect_configs
from .hunt import scan_logs
from .repoaudit import audit_repo


def assess(repo: Path | None = None, configs: list[Path] | None = None,
           access: list[Path] | None = None, errors: list[Path] | None = None,
           events: list[Path] | None = None, iocs: Path | None = None,
           local: bool = False) -> dict:
    reports = []
    if repo is not None:
        reports.append(audit_repo(repo))
    if configs:
        reports.append(inspect_configs(configs))
    if access or errors or events:
        reports.append(scan_logs(access, errors, events, iocs))
    if local:
        from patchproof.probes import local_scan
        proof = local_scan()
        overall = proof['overall']
        sev = 'high' if overall in ('AT_RISK', 'RESTART_REQUIRED', 'INTEGRITY_MISMATCH') else 'info'
        note = f'Observed runtime assessment: {overall}. Review separate full verify --local JSON for provenance.'
        reports.append(envelope('verify-summary', [
            {'severity': sev, 'rule_id': 'RUNTIME_'+overall, 'source': 'local host',
             'message': note, 'evidence': 'partial summary; not a proof of non-exploitability'}],
             notes=proof.get('limitations', [])))
    if not reports:
        raise ValueError('Supply at least one input: --repo, --config, logs or --local')
    findings = []
    limits = []
    for r in reports:
        findings.extend(r['findings'])
        limits.extend(r.get('limitations', []))
    limits.append('Combined findings are separate evidence streams. Correlation and remediation are human decisions.')
    return envelope('assess', findings, notes=list(dict.fromkeys(limits)))
