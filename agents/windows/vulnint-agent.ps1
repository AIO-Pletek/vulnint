<#
.SYNOPSIS
    VulnInt Windows Agent — collects OS info, hotfixes (KBs), and installed
    software from the registry, and reports them to the VulnInt API.

.DESCRIPTION
    Reads packages from the Uninstall registry hives (faster and more
    reliable than Win32_Product, which triggers MSI repair). Posts the
    inventory to /api/v1/inventory using the X-Agent-Token header.

    Designed for PowerShell 5.1+ (built into Windows Server 2016+) so it
    runs without external dependencies.

.PARAMETER ConfigPath
    Path to the agent config file (default: C:\ProgramData\VulnInt\agent.json)

.PARAMETER Once
    Run a single collection cycle and exit (used by Scheduled Task).

.EXAMPLE
    .\vulnint-agent.ps1 -Once
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = 'C:\ProgramData\VulnInt\agent.json',
    [switch]$Once
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Logging ───────────────────────────────────────────────────────────────────
$LogDir = Join-Path $env:ProgramData 'VulnInt'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$LogFile = Join-Path $LogDir 'agent.log'

function Write-Log {
    param([string]$Level, [string]$Message)
    $line = "{0} [{1}] {2}" -f (Get-Date -Format o), $Level, $Message
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    Write-Host $line
}

# ─── Config ────────────────────────────────────────────────────────────────────
function Load-Config {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "Config not found at $Path. Run Install-Agent.ps1 first."
    }
    $cfg = Get-Content $Path -Raw | ConvertFrom-Json

    foreach ($k in @('ApiUrl','AgentToken')) {
        $env_name = "VULNINT_$($k.ToUpper())"
        if ($env:$env_name) { $cfg.$k = $env:$env_name }
    }

    if ([string]::IsNullOrWhiteSpace($cfg.ApiUrl) -or
        [string]::IsNullOrWhiteSpace($cfg.AgentToken)) {
        throw "ApiUrl and AgentToken must be set in $Path"
    }
    return $cfg
}

# ─── OS detection ──────────────────────────────────────────────────────────────
function Get-OsInfo {
    $ci = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        os_family    = 'windows'
        os_version   = if ($ci) { "$($ci.Caption) $($ci.Version)" } else { [System.Environment]::OSVersion.VersionString }
        kernel       = if ($ci) { $ci.Version } else { $null }
        hostname     = [System.Net.Dns]::GetHostName()
        fqdn         = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
    }
}

# ─── Hotfix (KB) enumeration ──────────────────────────────────────────────────
function Get-Hotfixes {
    try {
        $hf = Get-HotFix -ErrorAction Stop |
              Where-Object { $_.HotFixID -match 'KB\d+' } |
              ForEach-Object {
                  [pscustomobject]@{
                      name    = $_.HotFixID
                      version = if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { '' }
                      arch    = $null
                      epoch   = $null
                      source  = 'kb'
                  }
              }
        return @($hf)
    } catch {
        Write-Log 'WARN' "Get-HotFix failed: $($_.Exception.Message)"
        return @()
    }
}

# ─── Installed software (from registry — fast, safe) ─────────────────────────
function Get-InstalledSoftware {
    $hives = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $items = foreach ($h in $hives) {
        Get-ItemProperty -Path $h -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and -not $_.SystemComponent }
    }
    $items |
        Sort-Object DisplayName -Unique |
        ForEach-Object {
            [pscustomobject]@{
                name    = "$($_.DisplayName)"
                version = if ($_.DisplayVersion) { "$($_.DisplayVersion)" } else { '0' }
                arch    = if ($_.PSPath -match 'WOW6432Node') { 'x86' } else { 'x64' }
                epoch   = $null
                source  = 'msi'
            }
        }
}

# ─── Security audit ─────────────────────────────────────────────────────────
function Get-SecurityAudit {
    $audit = [ordered]@{}

    # -- Firewall profiles ----------------------------------------------------
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        $fwProfiles = [ordered]@{}
        foreach ($p in $profiles) {
            $fwProfiles[$p.Name.ToLower()] = $p.Enabled -eq 'True'
        }
        $audit.firewall = [ordered]@{
            active   = ($profiles | Where-Object { $_.Enabled }).Count -gt 0
            type     = 'windows-firewall'
            default_policy = if (($profiles | Where-Object { $_.DefaultInboundAction -eq 'Block' }).Count -gt 0) { 'block' } else { 'allow' }
            profiles = $fwProfiles
        }
    } catch {
        $audit.firewall = [ordered]@{ active = $false; type = 'windows-firewall'; default_policy = 'unknown'; profiles = @{} }
    }

    # -- Windows Update status ------------------------------------------------
    $updates = [ordered]@{ last_updated = $null; pending_security = 0; auto_updates = $null }
    try {
        $auKey = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
        if (Test-Path $auKey) {
            $noAuto = (Get-ItemProperty $auKey -Name NoAutoUpdate -ErrorAction SilentlyContinue).NoAutoUpdate
            $updates.auto_updates = $noAuto -eq 0
        }
    } catch {}

    try {
        $latest = Get-HotFix -ErrorAction Stop |
                  Sort-Object InstalledOn -Descending |
                  Select-Object -First 1
        if ($latest -and $latest.InstalledOn) {
            $updates.last_updated = ([DateTime]$latest.InstalledOn).ToUniversalTime().ToString('o')
        }
    } catch {}

    $audit.updates = $updates

    # -- RDP / SMBv1 / UAC / Guest / PowerShell --------------------------------
    $misc = [ordered]@{}
    try {
        $tsKey = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
        $fDeny = (Get-ItemProperty $tsKey -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
        $nlaVal = (Get-ItemProperty "$tsKey\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
        $misc.rdp = [ordered]@{
            enabled      = $fDeny -eq 0
            nla_required = $nlaVal -eq 1
        }
    } catch {
        $misc.rdp = [ordered]@{ enabled = $false; nla_required = $false }
    }

    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        $misc.smbv1_enabled = $smb1.State -eq 'Enabled'
    } catch {
        $misc.smbv1_enabled = $false
    }

    try {
        $lua = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
        $misc.uac_enabled = $lua -eq 1
    } catch {
        $misc.uac_enabled = $true
    }

    try {
        $guest = Get-LocalUser -Name Guest -ErrorAction Stop
        $misc.guest_enabled = $guest.Enabled
    } catch {
        $misc.guest_enabled = $false
    }

    try {
        $misc.powershell_execution_policy = (Get-ExecutionPolicy -Scope LocalMachine -ErrorAction Stop).ToString()
    } catch {
        $misc.powershell_execution_policy = 'Unknown'
    }

    $audit.misc = $misc

    # -- Listening services ---------------------------------------------------
    $svc = [ordered]@{ listening = @() }
    try {
        $conns = Get-NetTCPConnection -State Listen -ErrorAction Stop
        $entries = foreach ($c in $conns) {
            $proc = $null
            try { $proc = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch {}
            [ordered]@{
                port    = $c.LocalPort
                bind    = $c.LocalAddress
                service = if ($proc) { "$proc" } else { 'unknown' }
            }
        }
        $svc.listening = @($entries)
    } catch {}
    $audit.services = $svc

    return $audit
}

# ─── HTTP send ────────────────────────────────────────────────────────────────
function Send-Inventory {
    param($Cfg, $Payload)

    $url = $Cfg.ApiUrl.TrimEnd('/') + '/api/v1/inventory'
    $headers = @{
        'Content-Type'   = 'application/json'
        'X-Agent-Token'  = $Cfg.AgentToken
        'User-Agent'     = 'vulnint-agent-windows/1.0'
    }

    # Force TLS 1.2+ for older Windows Server hosts
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

    if (-not $Cfg.VerifyTls) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }

    $json = $Payload | ConvertTo-Json -Depth 6 -Compress
    Invoke-RestMethod -Method POST -Uri $url -Headers $headers -Body $json -TimeoutSec 60
}

# ─── Queue (offline retry) ────────────────────────────────────────────────────
function Get-QueueDir { Join-Path $env:ProgramData 'VulnInt\queue' }

function Enqueue-Payload {
    param($Payload)
    $qd = Get-QueueDir
    if (-not (Test-Path $qd)) { New-Item -ItemType Directory -Path $qd -Force | Out-Null }
    $file = Join-Path $qd ((Get-Date -Format 'yyyyMMddTHHmmss') + '-' + [guid]::NewGuid().ToString().Substring(0,8) + '.json')
    $Payload | ConvertTo-Json -Depth 6 -Compress | Set-Content $file -Encoding UTF8
    Write-Log 'WARN' "Queued payload to $file"
}

function Drain-Queue {
    param($Cfg)
    $qd = Get-QueueDir
    if (-not (Test-Path $qd)) { return 0 }
    $sent = 0
    foreach ($f in Get-ChildItem $qd -Filter '*.json' | Sort-Object Name) {
        try {
            $payload = Get-Content $f.FullName -Raw | ConvertFrom-Json
            Send-Inventory -Cfg $Cfg -Payload $payload | Out-Null
            Remove-Item $f.FullName -Force
            $sent++
        } catch {
            Write-Log 'WARN' "Replay failed; will retry: $($_.Exception.Message)"
            break
        }
    }
    return $sent
}

# ─── Main ──────────────────────────────────────────────────────────────────────
function Invoke-Run {
    $cfg = Load-Config -Path $ConfigPath
    $os = Get-OsInfo

    $packages = @()
    $packages += Get-Hotfixes
    $packages += Get-InstalledSoftware

    $payload = [ordered]@{
        hostname        = $os.fqdn
        os_family       = 'windows'
        os_version      = $os.os_version
        kernel          = $os.kernel
        cpanel_version  = $null
        packages        = $packages
        raw_payload     = @{
            agent_version = '1.0.0'
            collected_at  = (Get-Date).ToUniversalTime().ToString('o')
            kb_count      = ($packages | Where-Object { $_.source -eq 'kb' }).Count
            sw_count      = ($packages | Where-Object { $_.source -eq 'msi' }).Count
        }
        audit           = Get-SecurityAudit
    }

    Write-Log 'INFO' "Collected $($packages.Count) entries (KBs + software)"

    $drained = Drain-Queue -Cfg $cfg
    if ($drained -gt 0) { Write-Log 'INFO' "Replayed $drained queued reports" }

    try {
        $resp = Send-Inventory -Cfg $cfg -Payload $payload
        Write-Log 'INFO' "Ingested: inventory_id=$($resp.inventory_id) packages=$($resp.package_count)"
    } catch {
        $msg = $_.Exception.Message
        $statusCode = 0
        if ($_.Exception.Response) {
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        }
        if ($statusCode -in 401,403) {
            Write-Log 'ERROR' "Auth rejected: $msg"
            exit 3
        }
        Write-Log 'WARN' "Send failed: $msg"
        Enqueue-Payload -Payload $payload
        exit 1
    }
}

try {
    Invoke-Run
    exit 0
} catch {
    Write-Log 'ERROR' "Unhandled: $($_.Exception.Message)"
    exit 4
}
