"""Human, JSON and SARIF report formatters."""
import json


def text_report(report: dict) -> str:
    lines = [f"PatchProof v0.1  |  PHP2Shell  |  mode={report['mode']}",
             f"Overall runtime: {report['overall']}",
             f"Ubuntu: {report['ubuntu_version'] or 'unknown / not Ubuntu'}",
             '']
    if not report['packages'] and report['mode'] != 'version-only':
        lines.append('No qualifying PHP runtime packages found in dpkg database.')
    for pkg in report['packages']:
        a = pkg['assessment']
        lines.extend([f"[{a['status']}] {pkg['name']}  {pkg['version']}",
                      f"  threshold: {a.get('threshold', 'unavailable')}",
                      f"  provenance corroborated: {a.get('provenance_verified', False)}",
                      f"  why: {a['reason']}",
                      f"  source: {a.get('reference', 'none')}"])
    if report['cli']:
        lines.append(f"\nCLI: PHP {report['cli']['version']} ({report['cli']['assessment']['status']})")
    if report['web_processes']:
        lines.append('\nObserved web worker processes:')
        for p in report['web_processes']:
            lines.append(f"  PID={p['pid']} {p['kind']} {p.get('branch')}  {p['binary_state']}"
                         f"  integrity={p.get('package_file_integrity', 'UNAVAILABLE')}  => {p['assessment']}")
    elif report['mode'] != 'version-only':
        lines.append('\nWeb workers: none observed (not evidence of absence).')
    lines.extend(['', 'A fixed package alone is NOT evidence that running web workers are fixed.',
                  'Patch the runtime and restart the serving worker; review JSON evidence.'])
    return '\n'.join(lines)


def sarif_report(report: dict) -> dict:
    results = []
    for pkg in report['packages']:
        assessment = pkg['assessment']
        status = assessment['status']
        level = 'error' if status == 'BELOW_FIXED_PACKAGE' else 'warning' if status == 'UNKNOWN' else 'note'
        results.append({'ruleId': 'PHP2ShellPackage', 'level': level,
                        'message': {'text': f"{pkg['name']} {pkg['version']}: {status}. {assessment['reason']}"},
                        'properties': {'status': status, 'package': pkg['name'], 'reference': assessment.get('reference')}})
    for p in report['web_processes']:
        severity = 'error' if p['assessment'] in ('AT_RISK_RUNTIME', 'RESTART_REQUIRED', 'INTEGRITY_MISMATCH') else 'warning' if p['assessment'] == 'UNKNOWN' else 'note'
        results.append({'ruleId': 'PHP2ShellRuntime', 'level': severity,
                        'message': {'text': f"PID {p['pid']} ({p['kind']}): {p['assessment']}"}})
    return {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'runs': [{
        'tool': {'driver': {'name': 'PHP2Shell PatchProof', 'version': '0.1.0', 'rules': [
            {'id': 'PHP2ShellPackage', 'shortDescription': {'text': 'PHP2Shell Ubuntu package advisory check'}},
            {'id': 'PHP2ShellRuntime', 'shortDescription': {'text': 'PHP2Shell active runtime freshness'}}]}},
        'results': results,
        'properties': {'overall': report['overall'], 'sourceDataset': report['dataset_date']}
    }]}


def serialize(report, fmt):
    if fmt == 'text':
        return text_report(report)
    if fmt == 'json':
        return json.dumps(report, indent=2, ensure_ascii=False)
    if fmt == 'sarif':
        return json.dumps(sarif_report(report), indent=2, ensure_ascii=False)
    raise ValueError('Invalid report format')
