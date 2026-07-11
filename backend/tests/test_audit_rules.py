"""Unit tests for the audit rules engine."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models.audit_finding import AuditCategory
from app.models.server import Environment, OSFamily, Server
from app.models.vulnerability import Severity
from app.services.audit_rules import evaluate_audit_rules


def _make_server(os_family: OSFamily) -> Server:
    """Create a minimal Server stub for rule evaluation."""
    s = Server(
        id=uuid.uuid4(),
        hostname="test-host",
        os_family=os_family,
        os_version="22.04",
        kernel="5.15.0-91-generic",
        environment=Environment.production,
        tags=[],
        is_active=True,
    )
    return s


class TestLinuxSSHRules:
    def test_root_login_yes_is_high(self):
        srv = _make_server(OSFamily.ubuntu)
        facts = {"ssh": {"root_login": "yes"}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "ssh_permit_root_login"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.high

    def test_root_login_prohibit_password(self):
        srv = _make_server(OSFamily.ubuntu)
        facts = {"ssh": {"root_login": "prohibit-password"}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "ssh_permit_root_login"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.high

    def test_root_login_no_is_clean(self):
        srv = _make_server(OSFamily.ubuntu)
        facts = {"ssh": {"root_login": "no"}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "ssh_permit_root_login"]
        assert len(f) == 0

    def test_root_login_unknown_is_low(self):
        srv = _make_server(OSFamily.ubuntu)
        facts = {"ssh": {}}  # no root_login key at all
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "ssh_permit_root_login"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.low

    def test_password_auth_yes(self):
        srv = _make_server(OSFamily.debian)
        facts = {"ssh": {"password_auth": "yes"}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "ssh_password_auth"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.medium

    def test_password_auth_no(self):
        srv = _make_server(OSFamily.ubuntu)
        facts = {"ssh": {"password_auth": "no"}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "ssh_password_auth"]
        assert len(f) == 0

    def test_weak_ciphers_detected(self):
        srv = _make_server(OSFamily.ubuntu)
        facts = {"ssh": {"ciphers": ["aes256-ctr", "3des-cbc", "aes128-cbc"]}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "ssh_weak_ciphers"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.medium
        assert "3des-cbc" in f[0]["description"]

    def test_strong_ciphers_only(self):
        srv = _make_server(OSFamily.ubuntu)
        facts = {"ssh": {"ciphers": ["aes256-ctr", "chacha20-poly1305@openssh.com"]}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "ssh_weak_ciphers"]
        assert len(f) == 0

    def test_protocol_1_critical(self):
        srv = _make_server(OSFamily.ubuntu)
        facts = {"ssh": {"protocol": "1"}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "ssh_protocol_1"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.critical


class TestLinuxFirewallRules:
    def test_no_firewall_high(self):
        srv = _make_server(OSFamily.ubuntu)
        facts = {"firewall": {"active": False, "type": "none"}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "firewall_disabled"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.high

    def test_firewall_active_is_clean(self):
        srv = _make_server(OSFamily.almalinux)
        facts = {"firewall": {"active": True, "type": "firewalld", "default_policy": "deny"}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "firewall_disabled"]
        assert len(f) == 0

    def test_default_allow_warns(self):
        srv = _make_server(OSFamily.rocky)
        facts = {"firewall": {"active": True, "type": "firewalld", "default_policy": "ACCEPT"}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "firewall_default_allow"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.medium


class TestLinuxUpdateRules:
    def test_stale_90d_is_high(self):
        srv = _make_server(OSFamily.ubuntu)
        old = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        facts = {"updates": {"last_updated": old}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "updates_stale_90d"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.high

    def test_stale_45d_is_medium(self):
        srv = _make_server(OSFamily.debian)
        old = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
        facts = {"updates": {"last_updated": old}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "updates_stale_30d"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.medium

    def test_recent_update_is_clean(self):
        srv = _make_server(OSFamily.ubuntu)
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        facts = {"updates": {"last_updated": recent}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"].startswith("updates_stale")]
        assert len(f) == 0

    def test_pending_security_updates(self):
        srv = _make_server(OSFamily.ubuntu)
        facts = {"updates": {"pending_security": 3}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "updates_pending_security"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.high

    def test_no_unattended_upgrades(self):
        srv = _make_server(OSFamily.ubuntu)
        facts = {"updates": {"auto_updates": False}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "updates_no_unattended"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.low


class TestLinuxServicesRules:
    def test_telnet_critical(self):
        srv = _make_server(OSFamily.ubuntu)
        facts = {"services": {"listening": [{"port": 23, "service": "telnet", "bind": "0.0.0.0"}]}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "service_telnet"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.critical

    def test_ftp_medium(self):
        srv = _make_server(OSFamily.debian)
        facts = {"services": {"listening": [{"port": 21, "service": "ftp", "bind": "0.0.0.0"}]}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "service_ftp"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.medium

    def test_ssh_is_ignored(self):
        srv = _make_server(OSFamily.ubuntu)
        facts = {"services": {"listening": [{"port": 22, "service": "ssh", "bind": "0.0.0.0"}]}}
        findings = evaluate_audit_rules(srv, facts)
        # SSH on 22 should not generate any finding
        f = [f for f in findings if f["category"] == AuditCategory.services and f["severity"] != Severity.low]
        assert len(f) == 0

    def test_open_port_public_low(self):
        srv = _make_server(OSFamily.ubuntu)
        facts = {"services": {"listening": [{"port": 8080, "service": "node", "bind": "0.0.0.0"}]}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "open_port_public"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.low


class TestWindowsRules:
    def test_firewall_disabled_profiles(self):
        srv = _make_server(OSFamily.windows)
        facts = {"firewall": {"active": True, "profiles": {"domain": True, "private": False, "public": True}}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "fw_disabled"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.high
        assert "private" in f[0]["description"]

    def test_firewall_all_enabled(self):
        srv = _make_server(OSFamily.windows)
        facts = {"firewall": {"active": True, "profiles": {"domain": True, "private": True, "public": True}}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "fw_disabled"]
        assert len(f) == 0

    def test_rdp_no_nla(self):
        srv = _make_server(OSFamily.windows)
        facts = {"misc": {"rdp": {"enabled": True, "nla_required": False}}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "rdp_nla_disabled"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.high

    def test_smbv1_critical(self):
        srv = _make_server(OSFamily.windows)
        facts = {"misc": {"smbv1_enabled": True}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "smbv1_enabled"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.critical

    def test_uac_disabled(self):
        srv = _make_server(OSFamily.windows)
        facts = {"misc": {"uac_enabled": False}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "uac_disabled"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.high

    def test_guest_enabled(self):
        srv = _make_server(OSFamily.windows)
        facts = {"misc": {"guest_enabled": True}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "guest_account"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.high

    def test_auto_updates_disabled(self):
        srv = _make_server(OSFamily.windows)
        facts = {"updates": {"auto_updates": False}}
        findings = evaluate_audit_rules(srv, facts)
        f = [f for f in findings if f["check_name"] == "updates_auto_disabled"]
        assert len(f) == 1
        assert f[0]["severity"] == Severity.high


class TestEmptyFacts:
    def test_linux_empty_produces_firewall_finding_and_ssh_unknown(self):
        srv = _make_server(OSFamily.ubuntu)
        findings = evaluate_audit_rules(srv, {})
        # Should get firewall_disabled + ssh_permit_root_login(low) at minimum
        checks = {f["check_name"] for f in findings}
        assert "firewall_disabled" in checks
        assert "ssh_permit_root_login" in checks

    def test_rule_exception_does_not_crash(self):
        """Malformed facts should not cause the entire evaluation to fail."""
        srv = _make_server(OSFamily.ubuntu)
        # updates expects a dict, give it something unexpected
        facts = {"updates": "not-a-dict"}
        findings = evaluate_audit_rules(srv, facts)
        # Should still return other findings
        assert isinstance(findings, list)
