import argparse
from pathlib import Path
import sys
from .probes import local_scan, rootfs_scan, docker_scan
from .report import serialize
from .policy import upstream_check, ubuntu_check, advisories


def main(argv=None):
    parser = argparse.ArgumentParser(prog='patchproof', description='Non-exploit PHP2Shell patch evidence checker')
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--local', action='store_true', help='Inventory this host and observed PHP workers')
    modes.add_argument('--rootfs', type=Path, metavar='PATH', help='Offline inspect a mounted image/filesystem')
    modes.add_argument('--docker-image', metavar='IMAGE', help='Inspect a LOCAL Docker image without starting it')
    modes.add_argument('--upstream-version', metavar='X.Y.Z', help='Compare a PHP release number (not runtime proof)')
    parser.add_argument('--format', choices=['text', 'json', 'sarif'], default='text')
    parser.add_argument('--output', type=Path, metavar='FILE')
    parser.add_argument('--strict', action='store_true', help='Exit 2 for risk/restart, 3 for unknown (CI fail-closed)')
    args = parser.parse_args(argv)
    try:
        if args.local:
            report = local_scan()
        elif args.rootfs:
            report = rootfs_scan(args.rootfs)
        elif args.docker_image:
            report = docker_scan(args.docker_image)
        else:
            assessed = upstream_check(args.upstream_version)
            report = {'schema_version': '0.1', 'tool': 'php2shell-patchproof', 'mode': 'version-only',
                      'dataset_date': advisories()['dataset_date'], 'cves': advisories()['cves'],
                      'ubuntu_version': None, 'packages': [], 'web_processes': [],
                      'cli': {'version': args.upstream_version, 'assessment': assessed}, 'overall': 'UNKNOWN',
                      'limitations': ['A version string alone cannot prove installed binary provenance or worker state.']}
        contents = serialize(report, args.format)
        if args.output:
            args.output.write_text(contents + '\n', encoding='utf-8')
        else:
            print(contents)
        if args.strict:
            return {'AT_RISK': 2, 'RESTART_REQUIRED': 2, 'INTEGRITY_MISMATCH': 2,
                    'UNKNOWN': 3}.get(report['overall'], 0)
        return 0
    except (ValueError, RuntimeError, OSError) as exc:
        print(f'patchproof: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
