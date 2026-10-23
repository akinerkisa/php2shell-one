"""Structured advisory policy. Never equate release numbers with runtime verification."""
import json
import re
from importlib.resources import files
from .versions import dpkg_compare, upstream_compare


def advisories():
    return json.loads(files('patchproof').joinpath('data/advisories.json').read_text())


def upstream_check(version: str) -> dict:
    data = advisories()
    m = re.fullmatch(r'(\d+\.\d+)\.(\d+)', version)
    if not m:
        return {"status": "UNKNOWN", "reason": "Not a stable X.Y.Z PHP release version"}
    branch = m.group(1)
    threshold = data['upstream'].get(branch)
    if not threshold:
        return {"status": "UNKNOWN", "reason": "No authoritative upstream threshold for this PHP branch"}
    candidate = upstream_compare(version, threshold) >= 0
    return {
        "status": "FIXED_VERSION" if candidate else "BELOW_FIXED_VERSION",
        "reason": "Upstream release threshold comparison only; does not prove installed binary provenance or active worker state",
        "threshold": threshold,
        "reference": f"https://www.php.net/releases/{threshold.replace('.', '_')}.php"
    }


def ubuntu_check(ubuntu_version: str, package_name: str, package_version: str,
                 official_provenance: bool = False) -> dict:
    data = advisories()
    info = data['ubuntu'].get(ubuntu_version)
    if not info:
        return {"status": "UNKNOWN", "reason": "Ubuntu release not in the signed-off advisory dataset"}
    branch = info['branch']
    allowed = {f'php{branch}-fpm', f'php{branch}-cli', f'php{branch}-cgi', f'libapache2-mod-php{branch}'}
    # Ubuntu 14.04 uses php5 package names, not php5.5-... package names.
    if ubuntu_version == '14.04':
        allowed = {'php5-fpm', 'php5-cli', 'php5-cgi', 'libapache2-mod-php5'}
    result = {"threshold": info['minimum'], "reference": info['advisory'],
              "support": info['support'], "provenance_verified": official_provenance}
    if package_name not in allowed:
        result.update(status='UNKNOWN', reason='Package does not match official advisory branch and runtime package naming')
        return result
    try:
        meets = dpkg_compare(package_version, info['minimum']) >= 0
    except ValueError:
        result.update(status='UNKNOWN', reason='Invalid Debian package version')
        return result
    result['threshold_met'] = meets
    if not official_provenance:
        result.update(status='UNKNOWN', reason='Matching package version alone cannot authenticate a vendor backport (no trusted apt origin evidence)')
    else:
        result.update(status='FIXED_PACKAGE' if meets else 'BELOW_FIXED_PACKAGE',
                      reason='Installed package version compared to Canonical USN; apt metadata corroborates an official Ubuntu repository')
    return result
