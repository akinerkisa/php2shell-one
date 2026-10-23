"""Repository-based PHP image pin review. No image pull or build."""
from __future__ import annotations

from pathlib import Path
import re

from patchproof.policy import upstream_check
from .common import envelope

FROM = re.compile(r'^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)', re.I)
COMPOSE_IMAGE = re.compile(r'^\s*image\s*:\s*[\'\"]?([^\s\'\"#]+)', re.I)
SKIP_DIRS = {'.git', '.venv', 'venv', 'node_modules', 'vendor', 'dist', 'build', '__pycache__', '.tox'}
MAX_FILE_BYTES = 2_000_000
VERSION = re.compile(r'^\d+\.\d+(?:\.\d+)?$')


def evaluate_image(image: str) -> dict | None:
    """Detect official PHP image tags; a tag is not cryptographic/runtime proof."""
    image = image.strip()
    if image.startswith('$') or '${' in image:
        return {'severity': 'info', 'rule_id': 'DYNAMIC_IMAGE', 'message': 'Dynamic image reference requires build-time resolution'}
    name = image.split('@', 1)[0]
    repo, sep, tag = name.rpartition(':')
    if not sep:
        repo, tag = name, ''
    basename = repo.split('/')[-1].lower()
    if basename != 'php':
        return None
    if '@sha256:' in image:
        return {'severity': 'info', 'rule_id': 'DIGEST_UNVERIFIED',
                'message': 'Digest-pinned PHP image: cannot determine whether the digest contains a security fix offline'}
    branch = tag.split('-', 1)[0]
    if not tag or branch in {'latest', 'stable'} or not VERSION.fullmatch(branch) or branch.count('.') != 2:
        return {'severity': 'medium', 'rule_id': 'MOVING_PHP_TAG',
                'message': 'PHP image tag is unpinned or ambiguous; resolve actual runtime package/digest'}
    assessed = upstream_check(branch)
    status = assessed.get('status', 'UNKNOWN')
    if status == 'BELOW_FIXED_VERSION':
        return {'severity': 'high', 'rule_id': 'PHP_TAG_BELOW_FIXED',
                'message': f'PHP image tag {tag} is below the upstream fixed version; replace and attest running image'}
    if status == 'FIXED_VERSION':
        return {'severity': 'info', 'rule_id': 'PHP_TAG_FIXED_CLAIM',
                'message': f'PHP image tag {tag} meets upstream threshold; tag alone does not prove deployed runtime safety'}
    return {'severity': 'medium', 'rule_id': 'PHP_TAG_VENDOR_UNKNOWN',
            'message': f'PHP image tag {tag} is outside covered upstream branches; check vendor fixes'}


def audit_repo(root: Path, max_files: int = 10000) -> dict:
    if not root.is_dir():
        raise ValueError('Repository path must be an existing directory')
    if max_files < 1 or max_files > 50000:
        raise ValueError('max_files must be 1..50000')
    findings = []
    visited = 0
    truncated = False
    for path in sorted(root.rglob('*')):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if not path.is_file():
            continue
        visited += 1
        if visited > max_files:
            truncated = True
            break
        if path.name != 'Dockerfile' and not path.name.startswith('Dockerfile.') and path.name not in {
            'compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml'}:
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            continue
        dockerfile = path.name.startswith('Dockerfile')
        for lineno, line in enumerate(path.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
            match = FROM.match(line) if dockerfile else COMPOSE_IMAGE.match(line)
            if not match:
                continue
            image = match.group(1)
            res = evaluate_image(image)
            if res:
                findings.append({**res, 'source': str(path.relative_to(root)), 'line': lineno, 'evidence': image[:160]})
    notes = ['Static Dockerfile/Compose review only; no image was pulled, built or executed.',
             'An image tag alone is not proof of the PHP version deployed or vendor backport state.',
             'Custom PHP builds, templating, ARG-based references and external image dependencies require manual inventory.']
    if truncated:
        notes.append('File scan limit reached; results may be incomplete')
    return envelope('repo-audit', findings, notes=notes)
