<#
.SYNOPSIS
    Install VulnInt Windows Agent as a Scheduled Task.

.PARAMETER ApiUrl
    Base URL of the VulnInt API.

.PARAMETER AgentToken
    Token issued when the server was registered.

.EXAMPLE
    PS> .\Install-Agent.ps1 -ApiUrl https://vulnint.example.com -AgentToken eyJ…
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ApiUrl,
    [Parameter(Mandatory)] [string]$AgentToken,
    [bool]$VerifyTls = $true,
    [int]$IntervalHours = 6
)

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Must run elevated (as Administrator).'
}

$InstallDir = Join-Path $env:ProgramFiles 'VulnInt'
$DataDir    = Join-Path $env:ProgramData 'VulnInt'
foreach ($d in @($InstallDir, $DataDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

$ScriptSrc = Join-Path $PSScriptRoot 'vulnint-agent.ps1'
$ScriptDst = Join-Path $InstallDir   'vulnint-agent.ps1'

# Try local copy first, then download from API
if (Test-Path $ScriptSrc) {
    Write-Host "  Using local vulnint-agent.ps1"
    Copy-Item -Path $ScriptSrc -Destination $ScriptDst -Force
} else {
    Write-Host "  Downloading vulnint-agent.ps1 from API..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    Invoke-WebRequest -Uri "$($ApiUrl.TrimEnd('/'))/api/v1/agents/windows/agent" -OutFile $ScriptDst -UseBasicParsing
}

$Config = [ordered]@{
    ApiUrl     = $ApiUrl.TrimEnd('/')
    AgentToken = $AgentToken
    VerifyTls  = [bool]$VerifyTls
}
$ConfigPath = Join-Path $DataDir 'agent.json'
$Config | ConvertTo-Json | Set-Content -Path $ConfigPath -Encoding UTF8
icacls $ConfigPath /inheritance:r /grant 'SYSTEM:F' 'Administrators:F' | Out-Null

# Scheduled Task — runs as SYSTEM, every $IntervalHours
$TaskName = 'VulnInt Agent'
schtasks /Delete /TN "$TaskName" /F 2>$null

$action = New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptDst`" -Once -ConfigPath `"$ConfigPath`""

$trigger1 = New-ScheduledTaskTrigger -AtStartup
$trigger1.Delay = "PT5M"
$trigger2 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
    -RepetitionInterval (New-TimeSpan -Hours $IntervalHours) `
    -RepetitionDuration ([TimeSpan]::MaxValue)

$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries `
    -AllowStartIfOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

Register-ScheduledTask -TaskName $TaskName `
    -Action $action -Trigger @($trigger1, $trigger2) `
    -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "✓ VulnInt agent installed."
Write-Host "  Script:  $ScriptDst"
Write-Host "  Config:  $ConfigPath"
Write-Host "  Task:    $TaskName  (every $IntervalHours h)"
Write-Host ""
Write-Host "Run once now:" -ForegroundColor Yellow
Write-Host "  Start-ScheduledTask -TaskName '$TaskName'"
