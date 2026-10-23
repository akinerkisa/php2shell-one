"""Policy-compatible Debian package version comparison, including epochs and '~'."""
import re


def _parts(s: str):
    if ':' in s:
        epoch, s = s.split(':', 1)
        if not epoch.isdigit():
            raise ValueError('Invalid dpkg epoch')
    else:
        epoch = '0'
    if '-' in s:
        upstream, revision = s.rsplit('-', 1)
    else:
        upstream, revision = s, '0'
    if not upstream or not re.match(r'^\d', upstream):
        raise ValueError('Invalid Debian upstream version')
    if not re.fullmatch(r'[A-Za-z0-9.+:~\-]+', s):
        raise ValueError('Invalid Debian version character')
    return int(epoch), upstream, revision


def _order(ch: str) -> int:
    if ch == '~':
        return -1
    if ch == '':
        return 0
    if ch.isascii() and ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            x = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            y = _order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if x != y:
                return (x > y) - (x < y)
            if i < len(a) and not a[i].isdigit():
                i += 1
            if j < len(b) and not b[j].isdigit():
                j += 1
        while i < len(a) and a[i] == '0':
            i += 1
        while j < len(b) and b[j] == '0':
            j += 1
        first_diff = 0
        while i < len(a) and j < len(b) and a[i].isdigit() and b[j].isdigit():
            if not first_diff:
                first_diff = (a[i] > b[j]) - (a[i] < b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def dpkg_compare(a: str, b: str) -> int:
    ea, ua, ra = _parts(a)
    eb, ub, rb = _parts(b)
    if ea != eb:
        return (ea > eb) - (ea < eb)
    result = _verrevcmp(ua, ub)
    return result or _verrevcmp(ra, rb)


def upstream_compare(a: str, b: str) -> int:
    """Compare simple X.Y.Z PHP release versions only."""
    def parse(s):
        if not re.fullmatch(r'\d+\.\d+\.\d+', s):
            raise ValueError('Expected PHP X.Y.Z (no prerelease)')
        return tuple(int(x) for x in s.split('.'))
    x, y = parse(a), parse(b)
    return (x > y) - (x < y)
