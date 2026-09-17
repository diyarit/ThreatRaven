# Runs the Pester suite under whichever PowerShell launched this file.
# CI calls it once via `powershell` (5.1) and once via `pwsh` (7+).
#   powershell -NoProfile -File .\Tests\Invoke-Tests.ps1
#   pwsh       -NoProfile -File .\Tests\Invoke-Tests.ps1
# Exit code 1 when any test fails or nothing ran.

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Path = '',

    # Optional path to a Pester 5+ manifest (skips Install-Module; used for local runs)
    [string]$PesterModulePath = ''
)

$ErrorActionPreference = 'Stop'

# $PSScriptRoot can be empty on PS 5.1 when launched with -File
$scriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDir)) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if ([string]::IsNullOrWhiteSpace($Path)) { $Path = Join-Path $scriptDir 'FeedHelpers.Tests.ps1' }
Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"

Get-Module Pester | Remove-Module -Force -ErrorAction SilentlyContinue

if (-not [string]::IsNullOrWhiteSpace($PesterModulePath)) {
    Import-Module $PesterModulePath -Force
}
else {
    $minimum = [version]'5.5.0'
    $pester = Get-Module -ListAvailable Pester |
        Where-Object { $_.Version -ge $minimum } |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if (-not $pester) {
        Write-Host 'Installing Pester 5...'
        try { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null } catch { }
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        Install-Module Pester -MinimumVersion $minimum -Force -Scope CurrentUser -SkipPublisherCheck -AllowClobber
        $pester = Get-Module -ListAvailable Pester |
            Where-Object { $_.Version -ge $minimum } |
            Sort-Object Version -Descending |
            Select-Object -First 1
    }
    if (-not $pester) { Write-Error 'Pester 5+ is not available'; exit 1 }
    Import-Module $pester.Path -Force
}

Write-Host "Pester $((Get-Module Pester).Version)"

$result = Invoke-Pester -Path $Path -Output Detailed -PassThru
if ($null -eq $result) { Write-Error 'Invoke-Pester returned nothing'; exit 1 }
if ($result.FailedCount -gt 0) { Write-Error "$($result.FailedCount) test(s) failed"; exit 1 }
if ($result.PassedCount -eq 0) { Write-Error 'No tests ran'; exit 1 }
Write-Host "All $($result.PassedCount) tests passed"
exit 0
