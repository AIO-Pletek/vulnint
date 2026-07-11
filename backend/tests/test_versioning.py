"""Unit tests for version comparison utilities."""
from __future__ import annotations

import pytest

from app.utils.versioning import cmp_dpkg, cmp_rpm, is_vulnerable, kb_matches


class TestDpkgCompare:
    def test_basic(self):
        assert cmp_dpkg("1.0", "1.0") == 0
        assert cmp_dpkg("1.0", "1.1") < 0
        assert cmp_dpkg("1.1", "1.0") > 0

    def test_with_revision(self):
        assert cmp_dpkg("1.0-1ubuntu1", "1.0-1ubuntu2") < 0

    def test_epoch(self):
        # epoch always wins
        assert cmp_dpkg("2:1.0", "1:9.9") > 0

    def test_security_fix(self):
        # Typical Ubuntu USN-style fix bump
        assert cmp_dpkg("8.2p1-4ubuntu0.5", "8.2p1-4ubuntu0.7") < 0


class TestRpmCompare:
    def test_basic(self):
        assert cmp_rpm("1.0", "1.0") == 0
        assert cmp_rpm("1.0", "1.1") < 0
        assert cmp_rpm("1.1", "1.0") > 0

    def test_release(self):
        assert cmp_rpm("1.0-1.el8", "1.0-2.el8") < 0

    def test_real_world_kernel(self):
        # CentOS-like: kernel-4.18.0-553.el8 vs 4.18.0-553.5.1.el8
        assert cmp_rpm("4.18.0-553.el8", "4.18.0-553.5.1.el8") < 0


class TestIsVulnerable:
    def test_dpkg_vulnerable_when_below_fix(self):
        assert is_vulnerable("1.0", fixed="2.0", os_family="ubuntu") is True

    def test_dpkg_not_vulnerable_when_at_fix(self):
        assert is_vulnerable("2.0", fixed="2.0", os_family="ubuntu") is False

    def test_dpkg_not_vulnerable_when_above_fix(self):
        assert is_vulnerable("3.0", fixed="2.0", os_family="debian") is False

    def test_rpm_vulnerable(self):
        assert is_vulnerable("1.0-1.el8", fixed="1.0-2.el8", os_family="almalinux") is True

    def test_rpm_not_vulnerable(self):
        assert is_vulnerable("1.0-3.el8", fixed="1.0-2.el8", os_family="rocky") is False

    def test_no_fix_assumes_vulnerable(self):
        # Without a fixed version, presence in the affected list = vulnerable
        assert is_vulnerable("1.0", fixed=None, os_family="ubuntu") is True


class TestKbMatches:
    def test_kb_matches(self):
        installed = ["KB5031356", "KB5034441", "KB5040434"]
        assert kb_matches(installed, "KB5034441") is True

    def test_kb_missing(self):
        installed = ["KB5031356"]
        assert kb_matches(installed, "KB5099999") is False

    def test_case_insensitive(self):
        installed = ["kb5034441"]
        assert kb_matches(installed, "KB5034441") is True
