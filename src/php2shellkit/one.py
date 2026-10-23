"""One-command, bounded PHP2Shell assessment."""
from __future__ import annotations

from pathlib import Path
import sys

from .assessment import assess


CONFIG_CANDIDATES = (
    'php.ini', '.user.ini', 'php-fpm.conf', 'www.conf',
    'config/php.ini', 'docker/php.ini', 'docker/php-fpm.conf',
)
ACCESS_CANDIDATES = ('access.log', 'logs/access.log', 'var/log/access.log')
ERROR_CANDIDATES = ('error.log', 'php-error.log', 'logs/error.log', 'logs/php-error.log')
EVENT_CANDIDATES = ('events.jsonl', 'logs/events.jsonl', 'edr.jsonl')


def _existing(root: Path, names: tuple[str, ...]) -> list[Path]:
    found = []
    for name in names:
        candidate = root / name
        if candidate.is_file():
            found.append(candidate)
    return found


def quick_report(root: Path, *, local: bool | None = None,
                 configs: list[Path] | None = None,
                 access: list[Path] | None = None,
                 errors: list[Path] | None = None,
                 events: list[Path] | None = None,
                 iocs: Path | None = None) -> dict:
    """Combine safe local evidence with no recursive log discovery or network access."""
    root = root.resolve()
    if not root.is_dir():
        raise ValueError('One report path must be an existing directory')
    auto_configs = _existing(root, CONFIG_CANDIDATES) if configs is None else configs
    auto_access = _existing(root, ACCESS_CANDIDATES) if access is None else access
    auto_errors = _existing(root, ERROR_CANDIDATES) if errors is None else errors
    auto_events = _existing(root, EVENT_CANDIDATES) if events is None else events
    use_local = sys.platform.startswith('linux') if local is None else local
    report = assess(root, auto_configs, auto_access, auto_errors, auto_events, iocs, use_local)
    report['command'] = 'one'
    report['limitations'].extend([
        'Quick mode inspects the selected repository and only fixed, documented local config/log filenames.',
        'No recursive log discovery, exploit request, network crawl or automatic remediation is performed.',
        'No findings does not mean the host or application is safe; unlisted files and unavailable evidence are not inspected.',
        'Use the dedicated verify and hunt commands when full provenance or explicit log paths are required.',
    ])
    report['quick_inputs'] = {
        'root': str(root), 'local_runtime': use_local,
        'configs': [str(p) for p in auto_configs],
        'access_logs': [str(p) for p in auto_access],
        'error_logs': [str(p) for p in auto_errors],
        'event_logs': [str(p) for p in auto_events],
    }
    return report
