"""Audit rules engine — evaluates raw agent facts against security policies.

Rules are simple callables that take (server, facts) and return either an
AuditFinding dict or None. The registry pattern makes it easy to add rules
without touching any other code.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.models.audit_finding import AuditCategory
from app.models.server import Server, OSFamily
from app.models.vulnerability import Severity

# ── helpers ──────────────────────────────────────────────────────────────


def _finding(
    check_name: str,
    category: AuditCategory,
    severity: Severity,
    title: str,
    description: str,
    remediation: str,
    evidence: dict | None = None,
) -> dict:
    return {
        "check_name": check_name,
        "category": category,
        "severity": severity,
        "status": "open",
        "title": title,
        "description": description,
        "remediation": remediation,
        "evidence": evidence or {},
    }


def _is_linux(s: Server) -> bool:
    return s.os_family in (
        OSFamily.ubuntu, OSFamily.debian, OSFamily.almalinux,
        OSFamily.rocky, OSFamily.cloudlinux,
    )


def _is_debian_family(s: Server) -> bool:
    return s.os_family in (OSFamily.ubuntu, OSFamily.debian)


def _is_rhel_family(s: Server) -> bool:
    return s.os_family in (OSFamily.almalinux, OSFamily.rocky, OSFamily.cloudlinux)


WEAK_SSH_CIPHERS = {
    "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "arcfour", "arcfour128", "arcfour256", "blowfish-cbc",
    "cast128-cbc", "rijndael-cbc@lysator.liu.se",
}
WEAK_SSH_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-ripemd160"}


# ── Linux rules ───────────────────────────────────────────────────────────


def _rule_ssh_root_login(server: Server, ssh: dict) -> Optional[dict]:
    value = (ssh or {}).get("root_login")
    if value is None:
        return _finding(
            "ssh_permit_root_login", AuditCategory.ssh, Severity.low,
            "SSH root login status unknown",
            "Could not determine PermitRootLogin from sshd_config.",
            "Ensure PermitRootLogin is set to 'no' in /etc/ssh/sshd_config.",
        )
    if value.lower() != "no":
        return _finding(
            "ssh_permit_root_login", AuditCategory.ssh, Severity.high,
            "Root login permitted over SSH",
            f"PermitRootLogin is set to '{value}'. Root should not be allowed to log in directly.",
            "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd.",
            {"permit_root_login": value},
        )
    return None


def _rule_ssh_password_auth(server: Server, ssh: dict) -> Optional[dict]:
    value = (ssh or {}).get("password_auth")
    if value is None:
        return None  # can't determine — don't raise noise
    if value.lower() == "yes":
        return _finding(
            "ssh_password_auth", AuditCategory.ssh, Severity.medium,
            "SSH password authentication enabled",
            "PasswordAuthentication is enabled. Key-based authentication is preferred.",
            "Set 'PasswordAuthentication no' and use SSH keys instead.",
            {"password_authentication": value},
        )
    return None


def _rule_ssh_protocol(server: Server, ssh: dict) -> Optional[dict]:
    protocol = (ssh or {}).get("protocol")
    if protocol and "1" in str(protocol) and "2" not in str(protocol):
        return _finding(
            "ssh_protocol_1", AuditCategory.ssh, Severity.critical,
            "SSH Protocol 1 enabled",
            "SSH Protocol 1 has known vulnerabilities and should never be used.",
            "Set 'Protocol 2' in /etc/ssh/sshd_config.",
            {"protocol": protocol},
        )
    return None


def _rule_ssh_weak_ciphers(server: Server, ssh: dict) -> Optional[dict]:
    ciphers = (ssh or {}).get("ciphers") or []
    if isinstance(ciphers, str):
        ciphers = [c.strip() for c in ciphers.split(",")]
    weak = [c for c in ciphers if c.lower() in WEAK_SSH_CIPHERS]
    if weak:
        return _finding(
            "ssh_weak_ciphers", AuditCategory.ssh, Severity.medium,
            "Weak SSH ciphers in use",
            f"Found {len(weak)} weak cipher(s): {', '.join(weak)}. These are susceptible to cryptographic attacks.",
            "Remove weak ciphers from the Ciphers directive in sshd_config.",
            {"weak_ciphers": weak},
        )
    return None


def _rule_ssh_weak_macs(server: Server, ssh: dict) -> Optional[dict]:
    macs = (ssh or {}).get("macs") or []
    if isinstance(macs, str):
        macs = [m.strip() for m in macs.split(",")]
    weak = [m for m in macs if m.lower() in WEAK_SSH_MACS]
    if weak:
        return _finding(
            "ssh_weak_macs", AuditCategory.ssh, Severity.medium,
            "Weak SSH MACs in use",
            f"Found {len(weak)} weak MAC(s): {', '.join(weak)}.",
            "Remove weak MACs from the MACs directive in sshd_config.",
            {"weak_macs": weak},
        )
    return None


def _rule_firewall_disabled(server: Server, fw: dict) -> Optional[dict]:
    fw = fw or {}
    active = fw.get("active")
    if active is False:
        fw_type = fw.get("type", "none")
        return _finding(
            "firewall_disabled", AuditCategory.firewall, Severity.high,
            "No active firewall detected",
            f"Firewall type '{fw_type}' is not active or no firewall is installed.",
            "Enable and configure ufw (Ubuntu/Debian) or firewalld (RHEL family) with a default-deny policy.",
            fw,
        )
    if active is None and fw.get("type") in (None, "none"):
        return _finding(
            "firewall_disabled", AuditCategory.firewall, Severity.high,
            "No firewall detected",
            "No host-based firewall (ufw, firewalld, or iptables) was found.",
            "Install and enable a host-based firewall.",
            fw,
        )
    return None


def _rule_firewall_default_allow(server: Server, fw: dict) -> Optional[dict]:
    policy = (fw or {}).get("default_policy", "").lower()
    if policy in ("accept", "allow"):
        return _finding(
            "firewall_default_allow", AuditCategory.firewall, Severity.medium,
            "Firewall default policy is ACCEPT",
            "Incoming traffic is allowed by default. A deny-by-default policy is safer.",
            "Set the default incoming policy to DENY: 'ufw default deny incoming' or equivalent.",
            {"default_policy": policy},
        )
    return None


def _rule_updates_stale(server: Server, updates: dict) -> List[dict]:
    findings = []
    last_str = (updates or {}).get("last_updated")
    if not last_str:
        return findings
    try:
        last = datetime.fromisoformat(last_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return findings

    now = datetime.now(timezone.utc)
    days = (now - last).days

    if days > 90:
        findings.append(_finding(
            "updates_stale_90d", AuditCategory.updates, Severity.high,
            f"OS not updated in {days} days",
            f"Last update was {days} days ago ({last.strftime('%Y-%m-%d')}). The system is critically out of date.",
            "Apply all pending OS security updates immediately.",
            {"last_updated": last_str, "days_since": days},
        ))
    elif days > 30:
        findings.append(_finding(
            "updates_stale_30d", AuditCategory.updates, Severity.medium,
            f"OS not updated in {days} days",
            f"Last update was {days} days ago ({last.strftime('%Y-%m-%d')}).",
            "Schedule regular OS patching.",
            {"last_updated": last_str, "days_since": days},
        ))
    return findings


def _rule_updates_pending_security(server: Server, updates: dict) -> Optional[dict]:
    pending = (updates or {}).get("pending_security", 0)
    if isinstance(pending, (int, float)) and pending > 0:
        return _finding(
            "updates_pending_security", AuditCategory.updates, Severity.high,
            f"{int(pending)} pending security update(s)",
            f"The server has {int(pending)} security update(s) waiting to be installed.",
            "Run package manager to install security updates.",
            {"pending_security": int(pending)},
        )
    return None


def _rule_updates_unattended(server: Server, updates: dict) -> Optional[dict]:
    auto = (updates or {}).get("auto_updates")
    if auto is False:
        return _finding(
            "updates_no_unattended", AuditCategory.updates, Severity.low,
            "Automatic security updates not configured",
            "Unattended-upgrades (or equivalent) is not enabled.",
            "Install and enable unattended-upgrades for automatic security patching.",
        )
    return None


def _rule_services_dangerous(server: Server, services: dict) -> List[dict]:
    findings = []
    listening = (services or {}).get("listening") or []
    DANGEROUS = {
        "telnet": ("service_telnet", Severity.critical, "Telnet service running", "Telnet transmits credentials in cleartext.", "Remove telnet and use SSH."),
        "ftp": ("service_ftp", AuditCategory.services, Severity.medium, "FTP service running", "FTP is unencrypted.", "Replace with SFTP or SCP."),
    }

    seen = set()
    for entry in listening:
        svc = (entry.get("service") or "").lower()
        port = entry.get("port", 0)
        if svc in ("ssh", "sshd", "http", "https", "dns", "ntp", "dhcp"):
            continue
        key = svc or str(port)
        if key in seen:
            continue
        if svc in DANGEROUS:
            check, cat, sev, title, desc, rem = DANGEROUS[svc]
            findings.append(_finding(check, cat, sev, title, desc, rem, {"port": port, "service": svc}))
            seen.add(key)

    # Check for non-standard ports bound to 0.0.0.0 (informational)
    for entry in listening:
        bind = (entry.get("bind") or entry.get("address") or "").strip()
        port = entry.get("port", 0)
        svc = (entry.get("service") or "unknown").lower()
        if bind in ("0.0.0.0", "::", "*") and port not in (22, 80, 443, 53):
            check = f"open_port_{port}_{svc}"
            if check in seen:
                continue
            seen.add(check)
            findings.append(_finding(
                "open_port_public", AuditCategory.services, Severity.low,
                f"Service '{svc}' exposed on port {port} (bound to {bind})",
                f"Port {port} ({svc}) is listening on all interfaces.",
                "Verify this service should be publicly accessible. Restrict to internal interfaces if not.",
                {"port": port, "service": svc, "bind": bind},
            ))
    return findings


# ── Windows rules ─────────────────────────────────────────────────────────


def _rule_win_fw_disabled(server: Server, fw: dict) -> Optional[dict]:
    profiles = (fw or {}).get("profiles") or {}
    disabled = [p for p, enabled in profiles.items() if not enabled]
    if disabled:
        return _finding(
            "fw_disabled", AuditCategory.firewall, Severity.high,
            f"Windows Firewall disabled on: {', '.join(disabled)}",
            f"Firewall profiles {', '.join(disabled)} are not active.",
            "Enable Windows Firewall on all profiles via 'Set-NetFirewallProfile -Enabled True'.",
            {"disabled_profiles": disabled},
        )
    return None


def _rule_win_rdp_nla(server: Server, misc: dict) -> Optional[dict]:
    rdp = (misc or {}).get("rdp") or {}
    if rdp.get("enabled") and not rdp.get("nla_required"):
        return _finding(
            "rdp_nla_disabled", AuditCategory.misc, Severity.high,
            "RDP enabled without Network Level Authentication",
            "RDP is accessible but NLA is not required, increasing the risk of credential-based attacks.",
            "Require NLA: Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1.",
            rdp,
        )
    return None


def _rule_win_updates_auto(server: Server, updates: dict) -> Optional[dict]:
    if (updates or {}).get("auto_updates") is False:
        return _finding(
            "updates_auto_disabled", AuditCategory.updates, Severity.high,
            "Windows automatic updates disabled",
            "Automatic updates are turned off via policy.",
            "Enable automatic Windows updates through Settings or Group Policy.",
        )
    return None


def _rule_win_last_update(server: Server, updates: dict) -> List[dict]:
    return _rule_updates_stale(server, updates)


def _rule_win_smbv1(server: Server, misc: dict) -> Optional[dict]:
    if (misc or {}).get("smbv1_enabled"):
        return _finding(
            "smbv1_enabled", AuditCategory.misc, Severity.critical,
            "SMBv1 protocol enabled",
            "SMBv1 is obsolete and was exploited by WannaCry and NotPetya. It should be disabled.",
            "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
            {"smbv1": True},
        )
    return None


def _rule_win_uac(server: Server, misc: dict) -> Optional[dict]:
    if (misc or {}).get("uac_enabled") is False:
        return _finding(
            "uac_disabled", AuditCategory.misc, Severity.high,
            "User Account Control (UAC) disabled",
            "UAC is turned off, allowing processes to run with full admin rights without prompting.",
            "Enable UAC: Set-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1.",
        )
    return None


def _rule_win_guest(server: Server, misc: dict) -> Optional[dict]:
    if (misc or {}).get("guest_enabled"):
        return _finding(
            "guest_account", AuditCategory.misc, Severity.high,
            "Guest account is enabled",
            "The built-in Guest account is active, which is a common attack vector.",
            "Disable the Guest account: Disable-LocalUser -Name Guest",
        )
    return None


def _rule_win_pwsh_policy(server: Server, misc: dict) -> Optional[dict]:
    policy = (misc or {}).get("powershell_execution_policy", "").lower()
    if policy == "unrestricted":
        return _finding(
            "pwsh_unrestricted", AuditCategory.misc, Severity.medium,
            "PowerShell execution policy is Unrestricted",
            "Unrestricted execution policy allows any script to run, including malicious ones.",
            "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine",
            {"execution_policy": policy},
        )
    return None


def _rule_win_dangerous_services(server: Server, services: dict) -> List[dict]:
    findings = []
    listening = (services or {}).get("listening") or []
    DANGEROUS = {3389: "RDP", 445: "SMB", 135: "RPC", 139: "NetBIOS"}
    for entry in listening:
        port = entry.get("port", 0)
        if port in DANGEROUS:
            name = DANGEROUS[port]
            findings.append(_finding(
                f"open_port_{port}", AuditCategory.services, Severity.low,
                f"{name} port {port} is open",
                f"Port {port} ({name}) is listening. Ensure it is firewalled or restricted.",
                f"Restrict port {port} to trusted networks via Windows Firewall.",
                {"port": port, "service": name},
            ))
    return findings


# ── rule registry ─────────────────────────────────────────────────────────

# Each entry: (applies_to_fn, facts_key, rule_fn)
# Multiple rules can consume the same facts key.
_LINUX_RULES: List = [
    ("ssh", _rule_ssh_root_login),
    ("ssh", _rule_ssh_password_auth),
    ("ssh", _rule_ssh_protocol),
    ("ssh", _rule_ssh_weak_ciphers),
    ("ssh", _rule_ssh_weak_macs),
    ("firewall", _rule_firewall_disabled),
    ("firewall", _rule_firewall_default_allow),
    ("updates", _rule_updates_stale),
    ("updates", _rule_updates_pending_security),
    ("updates", _rule_updates_unattended),
    ("services", _rule_services_dangerous),
]

_WINDOWS_RULES: List = [
    ("firewall", _rule_win_fw_disabled),
    ("updates", _rule_win_updates_auto),
    ("updates", _rule_win_last_update),
    ("services", _rule_win_dangerous_services),
    ("misc", _rule_win_rdp_nla),
    ("misc", _rule_win_smbv1),
    ("misc", _rule_win_uac),
    ("misc", _rule_win_guest),
    ("misc", _rule_win_pwsh_policy),
]


def evaluate_audit_rules(server: Server, facts: dict) -> List[dict]:
    """Run all applicable rules against the agent-reported facts.

    Returns a list of finding dicts suitable for AuditFindingRepo.upsert_findings().
    """
    if _is_linux(server):
        rules = _LINUX_RULES
    else:
        rules = _WINDOWS_RULES

    findings: List[dict] = []
    for facts_key, rule_fn in rules:
        section = facts.get(facts_key) or {}
        try:
            result = rule_fn(server, section)
        except Exception:
            # A single rule must never break the entire evaluation.
            continue
        if result is None:
            continue
        if isinstance(result, list):
            findings.extend(result)
        else:
            findings.append(result)
    return findings
