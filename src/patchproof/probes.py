"""Local, non-destructive inventory. Does not send network requests."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .policy import ubuntu_check, upstream_check, advisories

RUNTIME_PKG = re.compile(r'^(?:php\d+(?:\.\d+)?-(?:cli|fpm|cgi)|libapache2-mod-php\d+(?:\.\d+)?)$')
FPM_EXE = re.compile(r'php-fpm(\d+\.\d+)$')
LIBPHP = re.compile(r'/libphp(\d+\.\d+)\.so(?:\s+\(deleted\))?$')


def _run(cmd, timeout=8):
    try:
        cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=timeout, check=False)
        return cp.stdout if cp.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def os_release(content: str) -> dict:
    info = {}
    for line in content.splitlines():
        if '=' not in line or line.startswith('#'):
            continue
        k, value = line.split('=', 1)
        value = value.strip()
        if value and value[0] == value[-1] and value[0] in '\"\'':
            value = value[1:-1]
        info[k] = value
    return info


def dpkg_status(content: str) -> list:
    out = []
    for para in content.strip().split('\n\n'):
        fields = {}
        for line in para.splitlines():
            if not line or line[0].isspace() or ': ' not in line:
                continue
            k, val = line.split(': ', 1)
            fields[k] = val
        pkg = fields.get('Package', '')
        if fields.get('Status', '').endswith(' ok installed') and RUNTIME_PKG.fullmatch(pkg):
            out.append({'name': pkg, 'version': fields.get('Version', 'unknown')})
    return out


def apt_official_origin(package: str, version: str) -> bool:
    """Corroborate installed version appears in an official Canonical-hosted apt index.

    This is NOT cryptographic proof of the package currently on disk. It is
    intentionally conservative, leaving third-party mirrors UNKNOWN.
    """
    output = _run(['apt-cache', 'policy', package])
    if not output:
        return False
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if not re.match(r'^\s*(?:\*\*\*\s+)?' + re.escape(version) + r'\s+\d+\s*$', line):
            continue
        for continuation in lines[i+1:]:
            if re.match(r'^\s*(?:\*\*\*\s+)?\S+\s+\d+\s*$', continuation):
                break
            match = re.search(r'https?://([^/\s]+)', continuation)
            if match:
                host = match.group(1).split(':', 1)[0].lower()
                if host == 'ubuntu.com' or host.endswith('.ubuntu.com'):
                    return True
    return False


def _php_cli_version():
    php = shutil.which('php')
    if not php:
        return None
    # -n disables php.ini scanning; -r runs only a constant, not a PoC.
    output = _run([php, '-n', '-r', 'echo PHP_VERSION;'])
    return {'path': php, 'version': output.strip()} if output and re.fullmatch(r'\d+\.\d+\.\d+', output.strip()) else None


def _file_text(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return ''


def package_owns_binary(package: str, path: str) -> bool:
    """Require the running binary/module path to belong to the assessed dpkg package.

    Local path ownership is not a digital signature; packages can be tampered with.
    """
    if not path or path.endswith(' (deleted)') or not path.startswith('/'):
        return False
    text = _run(['dpkg-query', '-S', path])
    if not text:
        return False
    return any(re.match(r'^' + re.escape(package) + r'(?:\:[A-Za-z0-9-]+)?:\s', line)
               for line in text.splitlines())


def package_file_integrity(package: str, path: str) -> str:
    """Compare a package-owned file with dpkg's installed md5 manifest."""
    if not package or not path or path.endswith(' (deleted)') or not path.startswith('/'):
        return 'UNAVAILABLE'
    binary_package = _run(['dpkg-query', '-W', '-f=${binary:Package}', package])
    if not binary_package:
        return 'UNAVAILABLE'
    manifest = Path('/var/lib/dpkg/info') / f'{binary_package.strip()}.md5sums'
    wanted = path.lstrip('/')
    expected = None
    for line in _file_text(manifest).splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]{32})\s{2}(.+)', line)
        if match and match.group(2) == wanted:
            expected = match.group(1).lower()
            break
    if expected is None:
        return 'UNAVAILABLE'
    try:
        digest = hashlib.md5()
        with open(path, 'rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
    except OSError:
        return 'UNAVAILABLE'
    return 'VERIFIED' if digest.hexdigest() == expected else 'MISMATCH'


def _file_info(proc: Path, on_disk: str) -> str:
    """Check whether /proc/<pid>/exe inode matches current on-disk executable."""
    try:
        loaded = os.stat(proc / 'exe')
        installed = os.stat(on_disk)
        return 'CURRENT_BINARY' if (loaded.st_dev, loaded.st_ino) == (installed.st_dev, installed.st_ino) else 'STALE_BINARY'
    except OSError:
        return 'UNVERIFIED'


def processes() -> list:
    """Observe FPM and mod_php, never infer runtime patched from CLI alone."""
    proc = Path('/proc')
    if not proc.is_dir():
        return []
    result = []
    try:
        pids = sorted((p for p in proc.iterdir() if p.name.isdecimal()), key=lambda p: int(p.name))
    except OSError:
        return []
    for p in pids[:10000]:
        name = _file_text(p / 'comm').strip()
        if name.startswith('php-fpm'):
            try:
                exe = os.readlink(p / 'exe')
            except OSError:
                exe = ''
            # Strip ' (deleted)' only to find a basename; never use it as a real path.
            match = FPM_EXE.search(exe.replace(' (deleted)', ''))
            branch = match.group(1) if match else None
            state = _file_info(p, exe) if exe and not exe.endswith(' (deleted)') else ('STALE_BINARY' if exe else 'UNVERIFIED')
            pkg = f'php{branch}-fpm' if branch else ''
            owned = package_owns_binary(pkg, exe) if pkg else False
            result.append({'pid': int(p.name), 'kind': 'fpm', 'branch': branch,
                           'binary': exe, 'binary_state': state,
                           'package_owner_verified': owned,
                           'package_file_integrity': package_file_integrity(pkg, exe) if owned else 'UNAVAILABLE'})
        elif name in ('apache2', 'httpd'):
            maps = _file_text(p / 'maps')
            paths = set()
            for line in maps.splitlines():
                m = re.search(r'(/\S*libphp\d+\.\d+\.so(?: \(deleted\))?)$', line)
                if m:
                    paths.add(m.group(1))
            for modpath in sorted(paths):
                match = LIBPHP.search(modpath)
                if match:
                    state = 'STALE_BINARY' if modpath.endswith(' (deleted)') else 'UNVERIFIED'
                    # On disk shared libraries must be compared using the mapped inode.
                    if state != 'STALE_BINARY':
                        for line in maps.splitlines():
                            if line.endswith(modpath):
                                fields = line.split()
                                try:
                                    dev_major, dev_minor = (int(v, 16) for v in fields[3].split(':'))
                                    inode = int(fields[4])
                                    st = os.stat(modpath)
                                    state = ('CURRENT_BINARY' if (os.major(st.st_dev), os.minor(st.st_dev), st.st_ino) == (dev_major, dev_minor, inode) else 'STALE_BINARY')
                                except (OSError, ValueError, IndexError):
                                    state = 'UNVERIFIED'
                                break
                    pkg = f'libapache2-mod-php{match.group(1)}'
                    owned = package_owns_binary(pkg, modpath)
                    result.append({'pid': int(p.name), 'kind': 'mod_php', 'branch': match.group(1),
                                   'binary': modpath, 'binary_state': state,
                                   'package_owner_verified': owned,
                                   'package_file_integrity': package_file_integrity(pkg, modpath) if owned else 'UNAVAILABLE'})
    return result


def _inventory(ubuntu: str | None, pkgs: list, cli: dict | None, runtime: list,
               provenance_cb, mode: str) -> dict:
    readings = []
    for pkg in pkgs:
        official = bool(ubuntu and provenance_cb(pkg['name'], pkg['version']))
        evaluated = (ubuntu_check(ubuntu, pkg['name'], pkg['version'], official) if ubuntu
                     else {'status': 'UNKNOWN', 'reason': 'Not Ubuntu; vendor threshold unknown'})
        readings.append({**pkg, 'assessment': evaluated})
    if cli:
        cli['assessment'] = upstream_check(cli['version'])
        cli['note'] = 'CLI version is informational; not equivalent to active web runtime'
    process_results = []
    for r in runtime:
        component_pkg = ('php' + r['branch'] + '-fpm' if r['kind'] == 'fpm' else
                         'libapache2-mod-php' + r['branch']) if r['branch'] else None
        matched = next((x for x in readings if x['name'] == component_pkg), None)
        state = r['binary_state']
        ownership = bool(component_pkg and r.get('package_owner_verified', False))
        integrity = r.get('package_file_integrity', 'UNAVAILABLE')
        if state == 'STALE_BINARY':
            runtime_result = 'RESTART_REQUIRED'
        elif integrity == 'MISMATCH':
            runtime_result = 'INTEGRITY_MISMATCH'
        elif matched and ownership and integrity == 'VERIFIED' and matched['assessment']['status'] == 'FIXED_PACKAGE' and state == 'CURRENT_BINARY':
            runtime_result = 'FIXED_RUNTIME'
        elif matched and ownership and matched['assessment']['status'] == 'BELOW_FIXED_PACKAGE':
            runtime_result = 'AT_RISK_RUNTIME'
        else:
            runtime_result = 'UNKNOWN'
        process_results.append({**r, 'package': component_pkg, 'package_owner_verified': ownership,
                                'package_file_integrity': integrity,
                                'assessment': runtime_result})
    # No web processes reported must not be misreported as a secure runtime.
    if any(r['assessment'] == 'INTEGRITY_MISMATCH' for r in process_results):
        overall = 'INTEGRITY_MISMATCH'
    elif any(r['assessment'] == 'RESTART_REQUIRED' for r in process_results):
        overall = 'RESTART_REQUIRED'
    elif any(r['assessment'] == 'AT_RISK_RUNTIME' for r in process_results):
        overall = 'AT_RISK'
    elif process_results and all(r['assessment'] == 'FIXED_RUNTIME' for r in process_results):
        overall = 'FIXED_RUNTIME'
    else:
        overall = 'UNKNOWN'
    return {'schema_version': '0.1', 'tool': 'php2shell-patchproof', 'mode': mode,
            'cves': advisories()['cves'], 'dataset_date': advisories()['dataset_date'],
            'ubuntu_version': ubuntu, 'packages': readings, 'cli': cli,
            'web_processes': process_results, 'overall': overall,
            'limitations': ['This is advisory-backed version and runtime inventory, not exploit-based verification.',
                            'Installed bytes are checked against dpkg md5 manifests; these manifests are not package-signature attestation.',
                            'An unobserved or inaccessible runtime is UNKNOWN, never automatically FIXED.']}


def local_scan() -> dict:
    osr = os_release(_file_text(Path('/etc/os-release')))
    ubuntu = osr.get('VERSION_ID') if osr.get('ID', '').lower() == 'ubuntu' else None
    return _inventory(ubuntu, dpkg_status(_file_text(Path('/var/lib/dpkg/status'))),
                      _php_cli_version(), processes(), apt_official_origin, 'local')


def rootfs_scan(root: Path, mode: str = 'rootfs') -> dict:
    if not root.is_dir():
        raise ValueError('Rootfs path is not an existing directory')
    osr = os_release(_file_text(root / 'etc/os-release'))
    ubuntu = osr.get('VERSION_ID') if osr.get('ID', '').lower() == 'ubuntu' else None
    return _inventory(ubuntu, dpkg_status(_file_text(root / 'var/lib/dpkg/status')),
                      None, [], lambda _p, _v: False, mode)


def docker_scan(image: str) -> dict:
    """Inspect locally available image without ever starting a container."""
    if not shutil.which('docker'):
        raise RuntimeError('docker CLI is unavailable')
    if _run(['docker', 'image', 'inspect', image], timeout=15) is None:
        raise RuntimeError('Local Docker image not found or Docker daemon unavailable; no pull attempted')
    identifier = _run(['docker', 'create', '--network', 'none', '--read-only',
                       '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                       '--entrypoint', '/bin/true', image], timeout=20)
    if not identifier:
        raise RuntimeError('Could not create stopped image container')
    container = identifier.strip()
    try:
        with tempfile.TemporaryDirectory(prefix='patchproof-') as td:
            root = Path(td)
            for rel in ('etc/os-release', 'var/lib/dpkg/status'):
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                _run(['docker', 'cp', f'{container}:/{rel}', str(target)], timeout=20)
            report = rootfs_scan(root, mode='docker-image')
            report['image'] = image
            report['limitations'].append('Docker mode does not execute PHP or verify any running production container.')
            return report
    finally:
        _run(['docker', 'rm', '--force', '--volumes', container], timeout=20)
