"""Offline, privacy-preserving defensive hunting; no exploit traffic is generated."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from .common import envelope

COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<date>[^]]+)\] "(?P<method>\S+) (?P<uri>\S+) [^"]*" (?P<status>\d{3}) (?:\d+|-)'
)
OOM = re.compile(r'(?:Allowed memory size of .* exhausted|out of memory|zend_mm_heap corrupted|memory allocation failed)', re.I)
CRASH = re.compile(r'(?:segmentation fault|SIGSEGV|child .* exited on signal|worker .* crashed)', re.I)
PROGRESS = re.compile(r'PHP_SESSION_UPLOAD_PROGRESS|php-session-startup-rce-poc', re.I)
CANARY = re.compile(r'(?:nucleiBoundary|P2SMARK|nuclei-probe)', re.I)
WORKERS = {"php-fpm", "php-fpm8.2", "php-fpm8.3", "php-fpm8.4", "php-fpm8.5", "php-cgi", "apache2", "httpd", "lsphp"}
CHILD_TOOLS = {"sh", "bash", "dash", "curl", "wget", "nc", "ncat", "python", "python3", "perl", "socat"}
MAX_LINE_CHARS = 1_000_000


def _open_lines(path: Path):
    opener = gzip.open if str(path).endswith('.gz') else open
    with opener(path, 'rt', encoding='utf-8', errors='replace') as stream:
        while True:
            line = stream.readline(MAX_LINE_CHARS + 1)
            if not line:
                break
            if len(line) > MAX_LINE_CHARS:
                raise ValueError(f'Log line exceeds {MAX_LINE_CHARS} characters: {path}')
            yield line


def _time(s: str | None):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace('Z', '+00:00')).astimezone(timezone.utc)
    except (ValueError, TypeError):
        try:
            return datetime.strptime(s, '%d/%b/%Y:%H:%M:%S %z').astimezone(timezone.utc)
        except ValueError:
            return None


def read_iocs(path: Path | None) -> dict:
    if not path:
        return {'ips': set(), 'sha256': set()}
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError('IOC document must be an object')
    ips, hashes = set(), set()
    for val in data.get('ips', []):
        ips.add(str(ipaddress.ip_address(val)))
    for val in data.get('sha256', []):
        if not re.fullmatch(r'[0-9a-fA-F]{64}', val):
            raise ValueError('Invalid sha256 IOC')
        hashes.add(val.lower())
    return {'ips': ips, 'sha256': hashes}


def _client(ip: str, show: bool) -> str:
    return ip if show else 'client-' + hashlib.sha256(ip.encode()).hexdigest()[:12]


def _access_fields(line: str) -> dict | None:
    if line.lstrip().startswith('{'):
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                return None
            return {
                'ip': str(obj.get('remote_addr') or obj.get('client_ip') or obj.get('ip') or '-'),
                'method': str(obj.get('request_method') or obj.get('method') or '').upper(),
                'uri': str(obj.get('request_uri') or obj.get('path') or obj.get('uri') or '/'),
                'status': str(obj.get('status') or obj.get('status_code') or ''),
                'date': str(obj.get('time_iso8601') or obj.get('timestamp') or ''),
                'agent': str(obj.get('http_user_agent') or obj.get('user_agent') or ''),
            }
        except (ValueError, TypeError):
            return None
    m = COMBINED.match(line)
    if not m:
        return None
    return {**m.groupdict(), 'agent': ''}


def _finding(severity: str, rule_id: str, source: str, line: int | None, message: str, evidence: str = '') -> dict:
    return dict(severity=severity, rule_id=rule_id, source=source, line=line, message=message, evidence=evidence)


def scan_logs(access: list[Path] | None = None, error: list[Path] | None = None,
              events: list[Path] | None = None, ioc_file: Path | None = None,
              since: str | None = None, show_ips: bool = False,
              max_lines: int = 300000) -> dict:
    access, error, events = access or [], error or [], events or []
    if not (access or error or events):
        raise ValueError('At least one log file must be specified')
    if max_lines < 1 or max_lines > 5_000_000:
        raise ValueError('max_lines must be between 1 and 5000000')
    earliest = _time(since) if since else None
    if since and earliest is None:
        raise ValueError('--since must be ISO-8601')
    iocs = read_iocs(ioc_file)
    findings: list[dict] = []
    repeat = defaultdict(lambda: {'count': 0, 'source': '', 'line': 0})
    total = 0
    truncated = []
    for kind, paths in [('access', access), ('error', error), ('events', events)]:
        for path in paths:
            if not path.is_file():
                raise ValueError(f'Not a readable file: {path}')
            processed = 0
            for line_no, line in enumerate(_open_lines(path), 1):
                if processed >= max_lines:
                    truncated.append(str(path))
                    break
                processed += 1
                total += 1
                source = str(path)
                if kind == 'access':
                    fields = _access_fields(line)
                    if not fields:
                        continue
                    when = _time(fields['date'])
                    if earliest and when and when < earliest:
                        continue
                    ip = fields['ip']
                    client = _client(ip, show_ips)
                    uri = fields['uri']
                    try:
                        path_only = urlsplit(uri).path[:120]
                    except ValueError:
                        path_only = '(unparseable path)'
                    # No URL query, request body, session value or cookie is ever included in the output.
                    if ip in iocs['ips']:
                        findings.append(_finding('medium', 'IOC_IP', source, line_no,
                            f'IOC source observed: {client}', f'{fields["method"]} {path_only}'))
                    if PROGRESS.search(line):
                        findings.append(_finding('medium', 'SESSION_PROGRESS_PROBE', source, line_no,
                            f'Session progress marker visible in logged metadata: {client}', path_only))
                    if CANARY.search(line):
                        findings.append(_finding('low', 'SCANNER_CANARY', source, line_no,
                            f'Known scanner-like marker: {client}', path_only))
                    if fields['method'] == 'POST' and fields['status'].startswith('5'):
                        # Group evidence, not an exploit verdict.
                        key = (ip, path_only)
                        repeat[key]['count'] += 1
                        repeat[key]['source'] = source
                        repeat[key]['line'] = line_no
                elif kind == 'error':
                    if OOM.search(line):
                        findings.append(_finding('medium', 'PHP_OOM', source, line_no,
                            'PHP/server OOM-like diagnostic; correlate with HTTP activity'))
                    if CRASH.search(line):
                        findings.append(_finding('medium', 'WORKER_CRASH', source, line_no,
                            'Possible web/PHP worker crash; inspect worker lifecycle'))
                else:
                    try:
                        evt = json.loads(line)
                        if not isinstance(evt, dict):
                            continue
                    except ValueError:
                        continue
                    when = _time(str(evt.get('@timestamp') or evt.get('timestamp') or ''))
                    if earliest and when and when < earliest:
                        continue
                    proc = evt.get('process', {})
                    if not isinstance(proc, dict):
                        continue
                    par = proc.get('parent', {})
                    if not isinstance(par, dict):
                        par = {}
                    parent = str(par.get('name') or evt.get('parent_name') or '').lower()
                    name = str(proc.get('name') or '').lower()
                    if (parent in WORKERS or parent.startswith('php-fpm')) and name in CHILD_TOOLS:
                        findings.append(_finding('medium', 'PHP_CHILD_PROCESS', source, line_no,
                            f'Web/PHP process spawned a utility: {parent} -> {name}; investigate context'))
                    sha = evt.get('sha256') or (proc.get('hash', {}).get('sha256') if isinstance(proc.get('hash'), dict) else None)
                    if isinstance(sha, str) and sha.lower() in iocs['sha256']:
                        findings.append(_finding('high', 'IOC_SHA256', source, line_no,
                            'Exact hash matches a user-supplied IOC; validate file provenance', sha.lower()))
    for (ip, path_only), item in repeat.items():
        if item['count'] >= 5:
            findings.append(_finding('low', 'POST_5XX_BURST', item['source'], item['line'],
                f'{item["count"]} POST 5xx responses from {_client(ip, show_ips)} on one path', path_only))
    findings = sorted(findings, key=lambda f: (f['source'], f['line'] or 0, f['rule_id']))
    notes = [f'Scanned {total} lines; no exploit payloads or HTTP requests were generated.',
             'Heuristic matches are triage signals, never proof of PHP2Shell compromise.',
             'Default client identifiers are hashed; queries, cookies, POST bodies and raw error lines are not exported.',
             'Content within multipart POST bodies is usually absent from standard access logs.']
    if truncated:
        notes.append('Line limits reached for: ' + ', '.join(truncated))
    if since:
        notes.append('Unparseable log timestamps were not filtered by --since.')
    return envelope('hunt', findings, notes=notes)
