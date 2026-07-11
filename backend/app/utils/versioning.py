"""Version comparison utilities for dpkg, rpm, KB, and cPanel.

This is the core of the correlation engine. Each distro has its own
version semantics; we encapsulate them behind a uniform interface.
"""
from __future__ import annotations

import re
from typing import Optional

# rpm-vercmp is a small focused library that mirrors librpm semantics.
try:
    from rpm_vercmp import vercmp as _rpm_vercmp  # type: ignore
except Exception:  # pragma: no cover
    _rpm_vercmp = None

# Debian-aware comparison via debian-inspector (pure Python).
try:
    from debian_inspector.version import Version as _DebVersion  # type: ignore
except Exception:  # pragma: no cover
    _DebVersion = None


def cmp_dpkg(a: str, b: str) -> int:
    """Compare Debian/Ubuntu versions. Returns -1/0/1."""
    if _DebVersion is None:
        return _fallback_cmp(a, b)
    va, vb = _DebVersion.from_string(a), _DebVersion.from_string(b)
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


def cmp_rpm(a: str, b: str) -> int:
    """Compare RPM versions (RHEL/Alma/Rocky/CloudLinux). Returns -1/0/1."""
    if _rpm_vercmp is None:
        return _fallback_cmp(a, b)
    return _rpm_vercmp(a, b)


_fallback_split = re.compile(r"(\d+|[A-Za-z]+|[^\dA-Za-z]+)")


def _fallback_cmp(a: str, b: str) -> int:
    """Simple natural-order fallback when libs are missing."""
    pa = [t for t in _fallback_split.findall(a) if t.strip()]
    pb = [t for t in _fallback_split.findall(b) if t.strip()]
    for x, y in zip(pa, pb):
        if x.isdigit() and y.isdigit():
            xi, yi = int(x), int(y)
            if xi != yi:
                return -1 if xi < yi else 1
        else:
            if x != y:
                return -1 if x < y else 1
    if len(pa) != len(pb):
        return -1 if len(pa) < len(pb) else 1
    return 0


def is_vulnerable(installed: str, fixed: Optional[str], os_family: str) -> bool:
    """True if `installed` < `fixed` in the OS's version semantics.

    If fixed is None/empty -> still vulnerable (no fix yet).
    """
    if not fixed:
        return True
    fam = (os_family or "").lower()
    try:
        if fam in ("debian", "ubuntu"):
            return cmp_dpkg(installed, fixed) < 0
        if fam in ("almalinux", "rocky", "cloudlinux", "rhel", "centos", "fedora"):
            return cmp_rpm(installed, fixed) < 0
        if fam == "windows":
            # Windows uses KB matching, not version arithmetic
            return False
        return _fallback_cmp(installed, fixed) < 0
    except Exception:
        return False


def cpanel_is_vulnerable(installed: str, fixed: str) -> bool:
    """cPanel uses a TIER + version like 11.110.0.4. We compare them numerically."""
    def parts(v: str):
        return [int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v)]
    try:
        return parts(installed) < parts(fixed)
    except Exception:
        return False


def kb_matches(installed_kbs: list[str], required_kb: str) -> bool:
    """A Windows host has the patch if it has the required KB installed."""
    if not required_kb:
        return False
    rk = required_kb.upper().replace("KB", "")
    for kb in installed_kbs:
        if kb.upper().replace("KB", "") == rk:
            return True
    return False
