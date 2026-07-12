#!/usr/bin/env python3
"""VulnInt Linux Agent.

Collects installed packages, OS metadata, and (optionally) cPanel version,
then POSTs them to the VulnInt API as an inventory report.

Designed to require *no* third-party Python packages — only stdlib — so it
runs cleanly on minimal hosting boxes. Uses `dpkg-query` on Debian/Ubuntu
and `rpm -qa` on RHEL-family distros (Alma/Rocky/CloudLinux).

Usage:
    vulnint-agent.py --config /etc/vulnint/agent.yaml
    vulnint-agent.py --once          # collect once, exit
    vulnint-agent.py                  # daemon mode (loop with sleep)

Configuration (env vars override file):
    VULNINT_API_URL       https://vulnint.example.com
    VULNINT_AGENT_TOKEN   <token issued at server creation>
    VULNINT_INTERVAL      Seconds between runs in daemon mode (default 21600 = 6h)
    VULNINT_VERIFY_TLS    "true" / "false" (default true)
    VULNINT_QUEUE_DIR     /var/spool/vulnint  (used to retry when offline)
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOG = logging.getLogger("vulnint-agent")
DEFAULT_CONFIG = "/etc/vulnint/agent.yaml"
DEFAULT_QUEUE = "/var/spool/vulnint"


# ─── OS detection ──────────────────────────────────────────────────────────────

def parse_os_release() -> dict[str, str]:
    info: dict[str, str] = {}
    p = Path("/etc/os-release")
    if not p.exists():
        return info
    for line in p.read_text(errors="replace").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip().strip('"').strip("'")
    return info


def detect_os_family() -> tuple[str, str | None]:
    osr = parse_os_release()
    rid = (osr.get("ID") or "").lower()
    rid_like = (osr.get("ID_LIKE") or "").lower()
    version = osr.get("VERSION_ID") or osr.get("VERSION") or None
    if rid in {"ubuntu", "debian"}:
        return rid, version
    if rid in {"almalinux", "rocky", "cloudlinux"}:
        return rid, version
    if "rhel" in rid or "rhel" in rid_like or "fedora" in rid_like:
        # Map generic RHEL clones to almalinux as conservative default
        return "almalinux", version
    if "debian" in rid_like:
        return "debian", version
    return "other", version


def detect_kernel() -> str | None:
    try:
        return platform.release() or None
    except Exception:
        return None


def detect_cpanel() -> str | None:
    p = Path("/usr/local/cpanel/version")
    if p.exists():
        try:
            return p.read_text(errors="replace").strip()
        except Exception:
            return None
    return None


# ─── Package enumeration ───────────────────────────────────────────────────────

def collect_dpkg() -> list[dict[str, Any]]:
    """Collect installed Debian packages."""
    fmt = r"${Package}|${Version}|${Architecture}|${db:Status-Status}\n"
    try:
        out = subprocess.check_output(
            ["dpkg-query", "-W", "-f=" + fmt],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=120,
        )
    except (FileNotFoundError, subprocess.SubprocessError) as e:
        LOG.warning("dpkg-query failed: %s", e)
        return []
    pkgs: list[dict[str, Any]] = []
    for line in out.splitlines():
        if not line or "|" not in line:
            continue
        parts = line.split("|")
        if len(parts) < 4 or parts[3].strip() != "installed":
            continue
        pkgs.append({
            "name": parts[0].strip(),
            "version": parts[1].strip(),
            "arch": parts[2].strip() or None,
            "epoch": None,
            "source": "dpkg",
        })
    return pkgs


def collect_rpm() -> list[dict[str, Any]]:
    """Collect installed RPM packages."""
    fmt = "%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}\n"
    try:
        out = subprocess.check_output(
            ["rpm", "-qa", "--queryformat", fmt],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=120,
        )
    except (FileNotFoundError, subprocess.SubprocessError) as e:
        LOG.warning("rpm -qa failed: %s", e)
        return []
    pkgs: list[dict[str, Any]] = []
    for line in out.splitlines():
        if not line or "|" not in line:
            continue
        parts = line.split("|")
        if len(parts) < 5:
            continue
        name, epoch, ver, rel, arch = parts[:5]
        epoch = None if epoch in {"(none)", "", None} else epoch
        pkgs.append({
            "name": name.strip(),
            "version": f"{ver.strip()}-{rel.strip()}",
            "arch": arch.strip() or None,
            "epoch": epoch,
            "source": "rpm",
        })
    return pkgs


def collect_packages(os_family: str) -> list[dict[str, Any]]:
    if os_family in {"ubuntu", "debian"}:
        return collect_dpkg()
    if os_family in {"almalinux", "rocky", "cloudlinux"}:
        return collect_rpm()
    # Try both, return whichever yields results
    return collect_dpkg() or collect_rpm()


# ─── Security audit ────────────────────────────────────────────────────────────

def _parse_sshd_config(path: str = "/etc/ssh/sshd_config") -> dict[str, Any]:
    """Parse sshd_config into a dict of directive → value."""
    result: dict[str, Any] = {}
    p = Path(path)
    if not p.exists():
        return result
    try:
        for line in p.read_text(errors="replace").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split(None, 1)
            if len(parts) >= 2:
                result[parts[0].lower()] = parts[1].strip()
            elif len(parts) == 1:
                result[parts[0].lower()] = ""
    except Exception:
        pass
    return result


def _collect_ssh_audit(os_family: str) -> dict[str, Any]:
    """Gather SSH configuration posture."""
    ssh: dict[str, Any] = {}
    try:
        cfg = _parse_sshd_config()
        # PermitRootLogin: map variants to simple values
        rl = cfg.get("permitrootlogin", "").lower()
        ssh["root_login"] = rl if rl else "not_found"
        ssh["password_auth"] = cfg.get("passwordauthentication", "").lower()
        ssh["protocol"] = cfg.get("protocol", "")
        # Ciphers / MACs
        ciphers_raw = cfg.get("ciphers", "")
        ssh["ciphers"] = [c.strip() for c in ciphers_raw.split(",") if c.strip()] if ciphers_raw else []
        macs_raw = cfg.get("macs", "")
        ssh["macs"] = [m.strip() for m in macs_raw.split(",") if m.strip()] if macs_raw else []
        ssh["x11_forwarding"] = cfg.get("x11forwarding", "").lower()
        ssh["max_auth_tries"] = cfg.get("maxauthtries", "")
        ssh["client_alive_interval"] = cfg.get("clientaliveinterval", "")
        ssh["allow_agent_forwarding"] = cfg.get("allowagentforwarding", "")
        ssh["allow_tcp_forwarding"] = cfg.get("allowtcpforwarding", "")
    except Exception:
        pass
    return ssh


def _collect_firewall_audit() -> dict[str, Any]:
    """Check firewall status."""
    fw: dict[str, Any] = {"active": None, "type": "none", "default_policy": "unknown"}

    # Try ufw
    try:
        out = subprocess.check_output(
            ["ufw", "status"], stderr=subprocess.DEVNULL, text=True, timeout=10,
        )
        fw["type"] = "ufw"
        fw["active"] = "Status: active" in out
        if fw["active"]:
            for line in out.splitlines():
                line_s = line.strip()
                if line_s.lower().startswith("default:") and "deny" in line_s.lower():
                    fw["default_policy"] = "deny"
                elif line_s.lower().startswith("default:") and "allow" in line_s.lower():
                    fw["default_policy"] = "allow"
        return fw
    except Exception:
        pass

    # Try firewalld
    try:
        out = subprocess.check_output(
            ["firewall-cmd", "--state"], stderr=subprocess.DEVNULL, text=True, timeout=10,
        )
        fw["type"] = "firewalld"
        fw["active"] = "running" in out.lower()
        if fw["active"]:
            try:
                zone = subprocess.check_output(
                    ["firewall-cmd", "--get-default-zone"],
                    stderr=subprocess.DEVNULL, text=True, timeout=5,
                ).strip()
                target = subprocess.check_output(
                    ["firewall-cmd", "--zone", zone, "--get-target"],
                    stderr=subprocess.DEVNULL, text=True, timeout=5,
                ).strip().lower()
                fw["default_policy"] = target
            except Exception:
                pass
        return fw
    except Exception:
        pass

    # Fallback iptables
    try:
        out = subprocess.check_output(
            ["iptables", "-L", "INPUT", "-n"],
            stderr=subprocess.DEVNULL, text=True, timeout=10,
        )
        fw["type"] = "iptables"
        policy_line = out.splitlines()[0] if out.splitlines() else ""
        fw["active"] = "policy" in policy_line.lower()
        if "DROP" in policy_line or "REJECT" in policy_line:
            fw["default_policy"] = "deny"
        elif "ACCEPT" in policy_line:
            fw["default_policy"] = "allow"
        return fw
    except Exception:
        pass

    fw["active"] = False  # No firewall found
    return fw


def _collect_updates_audit(os_family: str) -> dict[str, Any]:
    """Get OS update status."""
    updates: dict[str, Any] = {
        "last_updated": None, "pending_security": 0, "auto_updates": None,
    }

    if os_family in ("ubuntu", "debian"):
        # Last update from apt history
        try:
            hp = Path("/var/log/apt/history.log")
            if hp.exists():
                for line in hp.read_text(errors="replace").splitlines():
                    if line.startswith("Start-Date:"):
                        ts = line.split("Start-Date:", 1)[1].strip()
                        # "2024-07-01  12:34:56"
                        try:
                            dt = datetime.strptime(ts.strip()[:19], "%Y-%m-%d  %H:%M:%S")
                            updates["last_updated"] = dt.replace(tzinfo=timezone.utc).isoformat()
                        except ValueError:
                            pass
                        break  # most recent is first
        except Exception:
            pass

        # Pending security updates
        try:
            out = subprocess.check_output(
                ["apt-get", "-s", "upgrade"], stderr=subprocess.DEVNULL, text=True, timeout=30,
            )
            count = 0
            for line in out.splitlines():
                if line.startswith("Inst ") and "security" in line.lower():
                    count += 1
            updates["pending_security"] = count
        except Exception:
            pass

        # Unattended-upgrades
        try:
            auto_paths = [
                "/etc/apt/apt.conf.d/20auto-upgrades",
                "/etc/apt/apt.conf.d/50unattended-upgrades",
            ]
            for ap in auto_paths:
                if Path(ap).exists():
                    content = Path(ap).read_text(errors="replace")
                    if "1" in content:
                        updates["auto_updates"] = True
                        break
            else:
                updates["auto_updates"] = False
        except Exception:
            pass

    elif os_family in ("almalinux", "rocky", "cloudlinux"):
        # Last DNF transaction
        try:
            hp = Path("/var/log/dnf.log")
            if hp.exists():
                text = hp.read_text(errors="replace")
                lines = text.splitlines()
                if lines:
                    # Parse ISO timestamps like "2024-07-01T12:34:56Z" or "2024-07-01T12:34:56+0000"
                    for line in reversed(lines):
                        try:
                            ts = line.split(" ")[0] if " " in line else line[:19]
                            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                            updates["last_updated"] = dt.isoformat()
                            break
                        except (ValueError, IndexError):
                            continue
        except Exception:
            pass

        # Pending security updates
        try:
            out = subprocess.check_output(
                ["dnf", "check-update", "--security"],
                stderr=subprocess.DEVNULL, text=True, timeout=60,
            )
            # Count non-header, non-empty lines
            count = sum(1 for line in out.splitlines() if line.strip() and not line.startswith("Last metadata"))
            updates["pending_security"] = max(0, count)
        except subprocess.CalledProcessError as e:
            # dnf check-update returns 100 if updates exist
            count = sum(1 for line in (e.output or "").splitlines() if line.strip() and not line.startswith("Last metadata"))
            updates["pending_security"] = max(0, count)
        except Exception:
            pass

        # DNF-automatic
        try:
            out = subprocess.check_output(
                ["systemctl", "is-enabled", "dnf-automatic.timer"],
                stderr=subprocess.DEVNULL, text=True, timeout=5,
            )
            updates["auto_updates"] = "enabled" in out.lower()
        except Exception:
            updates["auto_updates"] = False

    return updates


def _collect_services_audit() -> dict[str, Any]:
    """Enumerate listening services."""
    result: dict[str, Any] = {"listening": []}

    def _parse_ports(out: str) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for line in out.splitlines()[1:]:  # skip header
            line = line.strip()
            if not line or line.startswith("State"):
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            # ss format: Netid  State  Recv-Q Send-Q Local Address:Port Peer Address:Port
            # netstat: Proto Recv-Q Send-Q Local Address   Foreign Address  State  PID/Program
            local = parts[4] if len(parts) > 4 else ""
            service = parts[6] if len(parts) > 6 else ""
            if "/" in service:
                service = service.split("/", 1)[-1] if "/" in service else service
            if ":" in local:
                addr, port_str = local.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    continue
                entries.append({
                    "port": port,
                    "bind": addr,
                    "service": service.strip() or "unknown",
                })
        return entries

    try:
        out = subprocess.check_output(
            ["ss", "-tlnp"], stderr=subprocess.DEVNULL, text=True, timeout=10,
        )
        result["listening"] = _parse_ports(out)
    except Exception:
        try:
            out = subprocess.check_output(
                ["netstat", "-tlnp"], stderr=subprocess.DEVNULL, text=True, timeout=10,
            )
            result["listening"] = _parse_ports(out)
        except Exception:
            pass

    return result


def _collect_misc_audit() -> dict[str, Any]:
    """Miscellaneous security checks: kernel params, service versions, etc."""
    misc: dict[str, Any] = {}
    # World-writable files in /etc
    try:
        out = subprocess.check_output(
            ["find", "/etc", "-type", "f", "-perm", "-o+w"],
            stderr=subprocess.DEVNULL, text=True, timeout=10,
        )
        misc["world_writable_etc"] = len([l for l in out.splitlines() if l.strip()])
    except Exception:
        misc["world_writable_etc"] = -1

    # SUID/SGID count
    try:
        out = subprocess.check_output(
            ["find", "/", "-path", "/proc", "-prune", "-o",
             "-path", "/sys", "-prune", "-o",
             "-path", "/dev", "-prune", "-o",
             "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")",
             "-printf", "."],
            stderr=subprocess.DEVNULL, text=True, timeout=30,
        )
        misc["suid_sgid_count"] = len(out)
    except Exception:
        misc["suid_sgid_count"] = -1

    # Kernel security parameters
    _kernel_params = ["kernel.randomize_va_space", "kernel.kptr_restrict",
                      "kernel.dmesg_restrict", "kernel.yama.ptrace_scope",
                      "net.ipv4.ip_forward", "net.ipv4.conf.all.send_redirects",
                      "net.ipv4.conf.all.accept_source_route",
                      "fs.protected_symlinks", "fs.protected_hardlinks"]
    kernel: dict[str, str] = {}
    for param in _kernel_params:
        try:
            out = subprocess.check_output(
                ["sysctl", "-n", param], stderr=subprocess.DEVNULL, text=True, timeout=3,
            ).strip()
            kernel[param] = out
        except Exception:
            pass
    misc["kernel_params"] = kernel

    # Running service versions — capture version strings from known daemons
    service_versions: dict[str, str] = {}
    _checks = [
        ("sshd", ["sshd", "-?"]),
        ("apache2", ["apache2", "-v"]), ("httpd", ["httpd", "-v"]),
        ("nginx", ["nginx", "-v"]),
        ("mysql", ["mysqld", "--version"]), ("mariadb", ["mysqld", "--version"]),
        ("postgres", ["postgres", "--version"]),
        ("redis-server", ["redis-server", "--version"]),
        ("dockerd", ["dockerd", "--version"]),
        ("named", ["named", "-v"]), ("bind", ["named", "-v"]),
        ("exim4", ["exim", "-bV"]), ("postfix", ["postconf", "mail_version"]),
        ("dovecot", ["dovecot", "--version"]),
        ("php-fpm", ["php-fpm", "-v"]), ("php", ["php", "-v"]),
        ("node", ["node", "-v"]),
        ("java", ["java", "-version"]),
    ]
    for name, cmd in _checks:
        try:
            # Many services output version to stderr; capture both
            out = subprocess.check_output(
                cmd, stderr=subprocess.STDOUT, text=True, timeout=5,
            )
            # Grab the first meaningful line
            for line in out.splitlines():
                line = line.strip()
                if line and len(line) > 3:
                    service_versions[name] = line[:256]
                    break
        except Exception:
            pass
    misc["service_versions"] = service_versions

    return misc


def collect_audit(os_family: str) -> dict[str, Any]:
    """Collect security posture facts for the backend rules engine."""
    return {
        "ssh": _collect_ssh_audit(os_family),
        "firewall": _collect_firewall_audit(),
        "updates": _collect_updates_audit(os_family),
        "services": _collect_services_audit(),
        "misc": _collect_misc_audit(),
    }


# ─── HTTP transport ────────────────────────────────────────────────────────────

class ApiError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body[:300]}")
        self.status = status
        self.body = body


def post_inventory(api_url: str, token: str, payload: dict[str, Any], verify_tls: bool = True, timeout: int = 60) -> dict[str, Any]:
    url = api_url.rstrip("/") + "/api/v1/inventory"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Agent-Token": token,
            "User-Agent": "vulnint-agent-linux/1.0",
        },
    )
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = resp.read().decode("utf-8", errors="replace")
            return json.loads(data) if data else {}
    except urllib.error.HTTPError as e:
        raise ApiError(e.code, e.read().decode("utf-8", errors="replace")) from e
    except (urllib.error.URLError, socket.error) as e:
        raise ApiError(0, str(e)) from e


# ─── Offline queue ─────────────────────────────────────────────────────────────

def enqueue(queue_dir: str, payload: dict[str, Any]) -> Path:
    p = Path(queue_dir)
    p.mkdir(parents=True, exist_ok=True)
    fpath = p / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}.json"
    fpath.write_text(json.dumps(payload))
    return fpath


def drain_queue(queue_dir: str, api_url: str, token: str, verify_tls: bool) -> int:
    p = Path(queue_dir)
    if not p.exists():
        return 0
    sent = 0
    for fp in sorted(p.glob("*.json")):
        try:
            payload = json.loads(fp.read_text())
            post_inventory(api_url, token, payload, verify_tls=verify_tls)
            fp.unlink(missing_ok=True)
            sent += 1
        except ApiError as e:
            LOG.warning("queue replay failed (%s); will retry later", e)
            break
        except Exception as e:
            LOG.error("queue file %s corrupt: %s", fp, e)
            fp.unlink(missing_ok=True)
    return sent


# ─── Config loading ────────────────────────────────────────────────────────────

def load_config(path: str | None) -> dict[str, Any]:
    """Minimal YAML-ish loader (key: value pairs only). Avoids a yaml dep."""
    cfg: dict[str, Any] = {}
    if path and Path(path).exists():
        for line in Path(path).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            cfg[k.strip()] = v.strip().strip('"').strip("'")
    # Env overrides
    for k_env, k_cfg in [
        ("VULNINT_API_URL", "api_url"),
        ("VULNINT_AGENT_TOKEN", "agent_token"),
        ("VULNINT_INTERVAL", "interval"),
        ("VULNINT_VERIFY_TLS", "verify_tls"),
        ("VULNINT_QUEUE_DIR", "queue_dir"),
    ]:
        v = os.environ.get(k_env)
        if v is not None:
            cfg[k_cfg] = v
    return cfg


# ─── Main ──────────────────────────────────────────────────────────────────────

def collect_and_send(cfg: dict[str, Any]) -> int:
    os_family, os_version = detect_os_family()
    payload = {
        "hostname": socket.getfqdn() or socket.gethostname(),
        "os_family": os_family,
        "os_version": os_version,
        "kernel": detect_kernel(),
        "cpanel_version": detect_cpanel(),
        "packages": collect_packages(os_family),
        "raw_payload": {
            "agent_version": "1.0.0",
            "platform": platform.platform(),
            "collected_at": datetime.now(timezone.utc).isoformat(),
        },
        "audit": collect_audit(os_family),
    }
    LOG.info("collected %d packages on %s %s", len(payload["packages"]), os_family, os_version or "")
    api_url = cfg.get("api_url")
    token = cfg.get("agent_token")
    if not api_url or not token:
        LOG.error("missing api_url or agent_token in config")
        return 2
    verify_tls = str(cfg.get("verify_tls", "true")).lower() not in {"0", "false", "no"}
    queue_dir = cfg.get("queue_dir") or DEFAULT_QUEUE

    # Drain anything queued from prior failures
    drained = drain_queue(queue_dir, api_url, token, verify_tls)
    if drained:
        LOG.info("replayed %d queued reports", drained)

    try:
        result = post_inventory(api_url, token, payload, verify_tls=verify_tls)
        LOG.info("ingested: %s", result)
        return 0
    except ApiError as e:
        if e.status in (401, 403):
            LOG.error("auth failure (%s) — token rejected; not queuing", e)
            return 3
        LOG.warning("send failed (%s); queueing for retry", e)
        enqueue(queue_dir, payload)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnInt Linux agent")
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--once", action="store_true", help="collect once then exit")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    cfg = load_config(args.config)
    interval = int(cfg.get("interval") or 21600)

    if args.once:
        return collect_and_send(cfg)

    while True:
        try:
            collect_and_send(cfg)
        except Exception as e:
            LOG.exception("unhandled: %s", e)
        time.sleep(max(60, interval))


if __name__ == "__main__":
    sys.exit(main())
