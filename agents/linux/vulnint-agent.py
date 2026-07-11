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
