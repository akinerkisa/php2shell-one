"""Read-only PHP configuration heuristics; not a security attestation."""
from __future__ import annotations

from pathlib import Path
import re

from .common import envelope

SET = re.compile(r'^\s*(?:php_(?:admin_)?(?:value|flag)\[)?([\w.]+)\]?\s*=\s*(.*?)\s*$')


def inspect_configs(paths: list[Path]) -> dict:
    if not paths:
        raise ValueError('Supply one or more configuration files')
    findings = []
    for path in paths:
        if not path.is_file():
            raise ValueError(f'File not found: {path}')
        if path.stat().st_size > 2_000_000:
            raise ValueError(f'Config file too large: {path}')
        settings = {}
        for lineno, line in enumerate(path.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
            line = line.strip()
            if not line or line[0] in ';#':
                continue
            m = SET.match(line)
            if not m:
                continue
            key = m.group(1).lower()
            if key not in {'memory_limit', 'post_max_size', 'session.upload_progress.enabled', 'fatal_error_backtraces',
                           'display_errors', 'expose_php', 'upload_max_filesize', 'max_input_vars', 'max_input_nesting_level'}:
                continue
            value = m.group(2).split(';', 1)[0].split('#', 1)[0].strip().strip('"\'')
            settings[key] = (value, lineno)
        def add(k, sev, rule, message):
            if k in settings:
                value, line = settings[k]
                findings.append({'severity': sev, 'rule_id': rule, 'source': str(path), 'line': line,
                    'message': message, 'evidence': f'{k}={value[:40]}'})
        if 'session.upload_progress.enabled' in settings:
            v = settings['session.upload_progress.enabled'][0].lower()
            add('session.upload_progress.enabled', 'low' if v in {'on','1','true','yes'} else 'info',
                'SESSION_PROGRESS_CONFIG', 'Session upload progress enabled; disabling is a partial mitigation, not a patch' if v in {'on','1','true','yes'} else 'Session upload progress disabled; this is not complete mitigation')
        if 'memory_limit' in settings:
            v = settings['memory_limit'][0].lower()
            add('memory_limit', 'info', 'MEMORY_LIMIT_CONFIG',
                'Finite PHP memory limit observed; PHP project describes administrative -1 as a partial mitigation' if v != '-1' else
                'Unlimited PHP memory_limit observed: may increase system-level DoS exposure; not a complete mitigation')
        if 'fatal_error_backtraces' in settings:
            v = settings['fatal_error_backtraces'][0].lower()
            add('fatal_error_backtraces', 'low' if v in {'on','1','true','yes'} else 'info', 'BACKTRACE_CONFIG',
                'Fatal backtraces enabled; PHP 8.5 known attack path may be reachable' if v in {'on','1','true','yes'} else
                'Fatal backtraces disabled; partial hardening only')
        if 'display_errors' in settings and settings['display_errors'][0].lower() in {'on','1','true','yes'}:
            add('display_errors', 'low', 'ERROR_DISCLOSURE_CONFIG', 'display_errors enabled; may expose diagnostic details')
        if 'expose_php' in settings and settings['expose_php'][0].lower() in {'on','1','true','yes'}:
            add('expose_php', 'info', 'EXPOSE_PHP_CONFIG', 'PHP version may be exposed in HTTP response headers')
    return envelope('config-audit', findings, notes=[
        'Configuration files may not be loaded by the active PHP SAPI or may be overridden.',
        'No php.ini configuration completely mitigates PHP2Shell. Update runtime and restart workers.',
        'These observations are informational and do not establish vulnerability or safety.'])
