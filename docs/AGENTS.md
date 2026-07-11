# VulnInt agents

Two agents ship in this repo:

| Platform                          | Path                  | Runtime                    |
|-----------------------------------|-----------------------|----------------------------|
| Linux (Debian/Ubuntu/RHEL clones) | `agents/linux/`       | Python 3.6+ (stdlib only)  |
| Windows Server 2016+              | `agents/windows/`     | PowerShell 5.1+            |

Both agents:

1. Read the host's OS metadata, kernel, and (if present) cPanel version.
2. Enumerate installed packages — `dpkg-query` / `rpm -qa` on Linux,
   `Get-HotFix` (KBs) + Uninstall registry on Windows.
3. POST to `/api/v1/inventory` with `X-Agent-Token: <token>`.
4. Queue locally if the API is unreachable, retry on the next run.

There is **no port to open** on the agent host — communication is
outbound only.

---

## Linux

### Install

```bash
# On the target host, copy the agent files (or git pull this repo) and:
sudo bash agents/linux/install.sh https://vulnint.example.com <AGENT_TOKEN>
```

The installer:

- Installs the agent script to `/opt/vulnint/vulnint-agent.py`
- Writes config to `/etc/vulnint/agent.yaml` (mode 600, root)
- Creates a systemd service + timer (`vulnint-agent.timer`)
- Runs once immediately
- Schedules a recurring run every 6 hours with a randomized delay

### Verify

```bash
systemctl status vulnint-agent.timer
systemctl list-timers vulnint-agent.timer
journalctl -u vulnint-agent.service -n 50
sudo /opt/vulnint/vulnint-agent.py --once -v          # one-shot debug run
```

A successful run logs:

```
collected 1287 packages on ubuntu 22.04
ingested: {'inventory_id': '…', 'package_count': 1287}
```

### Configuration

The config file is plain key/value:

```yaml
api_url: "https://vulnint.example.com"
agent_token: "REPLACE_ME"
interval: 21600          # only used in daemon mode; the timer is canonical
verify_tls: true         # set false ONLY for self-signed dev
queue_dir: "/var/spool/vulnint"
```

Environment variables override the file (handy for testing):

```
VULNINT_API_URL  VULNINT_AGENT_TOKEN  VULNINT_INTERVAL  VULNINT_VERIFY_TLS
```

### Uninstall

```bash
sudo systemctl disable --now vulnint-agent.timer
sudo rm -f /etc/systemd/system/vulnint-agent.{service,timer}
sudo systemctl daemon-reload
sudo rm -rf /opt/vulnint /etc/vulnint /var/spool/vulnint
```

---

## Windows

### Install

In an elevated PowerShell on the target host, from the directory
containing both files:

```powershell
.\Install-Agent.ps1 -ApiUrl https://vulnint.example.com -AgentToken <TOKEN>
```

The installer:

- Copies the agent to `C:\Program Files\VulnInt\vulnint-agent.ps1`
- Writes config (JSON) to `C:\ProgramData\VulnInt\agent.json`,
  ACL'd to SYSTEM and Administrators only
- Registers a Scheduled Task **`VulnInt Agent`** running as SYSTEM,
  triggered at startup (5 min delay) and every 6 hours

### Verify

```powershell
Get-ScheduledTask -TaskName 'VulnInt Agent' | Get-ScheduledTaskInfo
Start-ScheduledTask -TaskName 'VulnInt Agent'         # one-shot run
Get-Content C:\ProgramData\VulnInt\agent.log -Tail 30
```

### What it collects

- **Hotfixes (KBs)** via `Get-HotFix` — these become packages with
  `source = "kb"`, used directly by the correlator's KB matcher.
- **Installed software** by reading `HKLM:\Software\…\Uninstall\*` and
  the WOW6432Node mirror. We deliberately **do not** call
  `Win32_Product` (`Get-WmiObject Win32_Product`) — it triggers MSI
  self-repair on every system in the domain and is a known cause of
  domain-wide CPU storms.

### Uninstall

```powershell
Unregister-ScheduledTask -TaskName 'VulnInt Agent' -Confirm:$false
Remove-Item -Recurse -Force "$env:ProgramFiles\VulnInt"
Remove-Item -Recurse -Force "$env:ProgramData\VulnInt"
```

---

## Troubleshooting

| Symptom                                         | Cause / fix                                                     |
|-------------------------------------------------|------------------------------------------------------------------|
| `auth rejected` / 401                           | Token typo or regenerated — issue a new token in the dashboard   |
| `URLError: certificate verify failed`           | Corporate MITM proxy — install its CA chain or set `verify_tls: false` (dev only) |
| Linux: nothing in `/var/spool/vulnint`           | Either the network is fine or the agent crashed — check `journalctl` |
| Windows: agent runs but no inventory in dashboard | Outbound blocked on 443 — Windows Firewall outbound rule        |
| Reports too small (zero packages)               | Wrong package manager — agent picks based on `/etc/os-release`. Check `os_family` in dashboard. |
