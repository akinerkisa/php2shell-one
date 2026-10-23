"""PHP2Shell One command line interface."""
from __future__ import annotations

import argparse
from importlib import resources
import json
from pathlib import Path
import sys

from patchproof.probes import local_scan, rootfs_scan, docker_scan
from patchproof.policy import advisories, upstream_check
from patchproof.report import serialize as proof_serialize
from . import __version__
from .common import write_report
from .configcheck import inspect_configs
from .assessment import assess
from .capabilities import one_status
from .one import quick_report
from .hunt import scan_logs
from .repoaudit import audit_repo
from .webcheck import web_head


RULES = ['modsecurity/request-limits.conf', 'modsecurity/no-multipart.example.conf',
         'nginx/request-limits.conf', 'sigma/php-worker-child-process.yml']


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='php2shell', description='PHP2Shell One (focused modules; no production exploit traffic)')
    p.add_argument('--version', action='version', version=__version__)
    subs = p.add_subparsers(dest='command', required=True)

    st = subs.add_parser('status', help='Offline advisory/CVE/patch reference summary')
    st.add_argument('--json', action='store_true')

    one = subs.add_parser('one', help='Generate one bounded local report from documented inputs')
    one.add_argument('path', nargs='?', type=Path, default=Path('.'))
    one.add_argument('--config', type=Path, action='append')
    one.add_argument('--access-log', type=Path, action='append')
    one.add_argument('--error-log', type=Path, action='append')
    one.add_argument('--events-json', type=Path, action='append')
    one.add_argument('--ioc-file', type=Path)
    one.add_argument('--local', action='store_true', help='Force local runtime inventory')
    one.add_argument('--no-local', action='store_true', help='Disable automatic Linux runtime inventory')
    report_args(one)
    capabilities = subs.add_parser('capabilities', help='Show module and validation readiness')
    report_args(capabilities)

    chk = subs.add_parser('verify', help='PatchProof package/runtime evidence and vendor checks')
    modes = chk.add_mutually_exclusive_group(required=True)
    modes.add_argument('--local', action='store_true')
    modes.add_argument('--rootfs', type=Path)
    modes.add_argument('--docker-image')
    modes.add_argument('--version', dest='php_version')
    chk.add_argument('--format', choices=['text', 'json', 'sarif'], default='text')
    chk.add_argument('--output', type=Path)
    chk.add_argument('--strict', action='store_true')

    hunt = subs.add_parser('hunt', help='Offline access/error/EDR JSONL log correlation')
    hunt.add_argument('--access-log', type=Path, action='append', default=[])
    hunt.add_argument('--error-log', type=Path, action='append', default=[])
    hunt.add_argument('--events-json', type=Path, action='append', default=[])
    hunt.add_argument('--ioc-file', type=Path)
    hunt.add_argument('--since', help='ISO8601 datetime; unparseable log timestamps cannot be filtered')
    hunt.add_argument('--max-lines', type=int, default=300000)
    hunt.add_argument('--show-ips', action='store_true', help='Show actual client IPs (default redacted)')
    report_args(hunt)

    repo = subs.add_parser('repo-audit', help='Review Dockerfiles and Compose PHP image pins offline')
    repo.add_argument('path', type=Path)
    repo.add_argument('--max-files', type=int, default=10000)
    report_args(repo)

    conf = subs.add_parser('config-audit', help='Inspect local PHP configuration files (heuristics)')
    conf.add_argument('paths', nargs='+', type=Path)
    report_args(conf)

    web = subs.add_parser('webcheck', help='One authorized HEAD request; headers only, not vulnerability scan')
    web.add_argument('url')
    web.add_argument('--authorized', action='store_true', help='Confirm permission for this exact target')
    web.add_argument('--timeout', type=float, default=5)
    report_args(web)

    composite = subs.add_parser('assess', help='Combine repo, PHP config and log signals into one offline report')
    composite.add_argument('--repo', type=Path)
    composite.add_argument('--config', type=Path, action='append', default=[])
    composite.add_argument('--access-log', type=Path, action='append', default=[])
    composite.add_argument('--error-log', type=Path, action='append', default=[])
    composite.add_argument('--events-json', type=Path, action='append', default=[])
    composite.add_argument('--ioc-file', type=Path)
    composite.add_argument('--local', action='store_true', help='Also summarize local worker evidence (Linux only)')
    report_args(composite)

    rules = subs.add_parser('rules', help='List/show conservative defensive configuration templates')
    rules.add_argument('action', choices=['list', 'show'])
    rules.add_argument('name', nargs='?', choices=RULES)
    return p


def report_args(p: argparse.ArgumentParser) -> None:
    p.add_argument('--format', choices=['text', 'json', 'csv', 'sarif', 'html'], default='text')
    p.add_argument('--output', type=Path)
    p.add_argument('--fail-on', choices=['never', 'high', 'medium'], default='never',
                   help='Exit 2 if severity meets threshold; not a vulnerability verdict')


def _threshold(report: dict, condition: str) -> int:
    if condition == 'never':
        return 0
    scores = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}
    minimum = 3 if condition == 'high' else 2
    return 2 if any(scores.get(f.get('severity', 'info'), 0) >= minimum for f in report.get('findings', [])) else 0


def run(args) -> int:
    if args.command == 'status':
        data = advisories()
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            print('PHP2Shell | CVE-2026-109618 & CVE-2026-109619')
            print('Pinned advisory dataset: ' + data['dataset_date'])
            for branch, version in sorted(data['upstream'].items()):
                print('  PHP ' + branch + ' -> ' + version + ' (first fixed upstream)')
            print('Other vendors may backport. Do not rely on PHP_VERSION alone.')
            for url in data['references']:
                print('  ' + url)
        return 0
    if args.command == 'one':
        if args.local and args.no_local:
            raise ValueError('--local and --no-local are mutually exclusive')
        local = True if args.local else False if args.no_local else None
        report = quick_report(args.path, local=local, configs=args.config,
                              access=args.access_log, errors=args.error_log,
                              events=args.events_json, iocs=args.ioc_file)
        write_report(report, args.format, args.output)
        return _threshold(report, args.fail_on)
    if args.command == 'capabilities':
        report = one_status()
        write_report(report, args.format, args.output)
        return _threshold(report, args.fail_on)
    if args.command == 'verify':
        if args.local:
            result = local_scan()
        elif args.rootfs:
            result = rootfs_scan(args.rootfs)
        elif args.docker_image:
            result = docker_scan(args.docker_image)
        else:
            check = upstream_check(args.php_version)
            data = advisories()
            result = {'schema_version': '0.1', 'tool': 'php2shell-patchproof', 'mode': 'version-only',
                      'dataset_date': data['dataset_date'], 'cves': data['cves'], 'ubuntu_version': None,
                      'packages': [], 'web_processes': [], 'cli': {'version': args.php_version, 'assessment': check},
                      'overall': 'UNKNOWN', 'limitations': ['Version strings are not a running web server patch attestation.']}
        output = proof_serialize(result, args.format)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output + '\n', encoding='utf-8')
        else:
            print(output)
        return {'AT_RISK': 2, 'RESTART_REQUIRED': 2, 'INTEGRITY_MISMATCH': 2,
                'UNKNOWN': 3}.get(result['overall'], 0) if args.strict else 0
    if args.command == 'hunt':
        report = scan_logs(args.access_log, args.error_log, args.events_json, args.ioc_file,
                           args.since, args.show_ips, args.max_lines)
    elif args.command == 'repo-audit':
        report = audit_repo(args.path, args.max_files)
    elif args.command == 'assess':
        report = assess(args.repo, args.config, args.access_log, args.error_log, args.events_json, args.ioc_file, args.local)
    elif args.command == 'config-audit':
        report = inspect_configs(args.paths)
    elif args.command == 'webcheck':
        report = web_head(args.url, args.authorized, args.timeout)
    elif args.command == 'rules':
        if args.action == 'list':
            print('\n'.join(RULES))
            return 0
        if not args.name:
            raise ValueError('rules show requires a template name; see rules list')
        print(resources.files('php2shellkit').joinpath('data/rules/' + args.name).read_text(encoding='utf-8'))
        return 0
    else:
        raise ValueError('Unknown subcommand')
    write_report(report, args.format, args.output)
    return _threshold(report, args.fail_on)


def main(argv=None) -> int:
    try:
        return run(parser().parse_args(argv))
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as exc:
        print('php2shell: ' + str(exc), file=sys.stderr)
        return 1
if __name__ == '__main__':
    sys.exit(main())
