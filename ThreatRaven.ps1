# ============================================================
# ThreatRaven.ps1 - APT Intelligence Feed Monitor
# Version: 4.0
#
# v4.0 changes:
#  - Fixed stored-XSS in generated reports (DOM-based rendering,
#    no inline JS string concatenation, CSP nonce, URL scheme guards)
#  - Fixed retry logic: permanent HTTP errors (400/401/404/410) no longer retried;
#    real fetch errors now surface in feed health
#  - -QuietMode now suppresses ALL console output
#  - Settings.ExportHealthReport from config.json is honored
#  - TLS 1.2+ enforced; certificate validation scoped to the run (no per-runspace race)
#  - Persistent state file (ThreatRavenState.json): automatic deduplication,
#    ETag/Last-Modified conditional requests, feed health history, NVD cache
#  - Server-side NVD CVE fetching (paginated, rate-limit aware, API key support)
#  - HTML/JS/CSS extracted to assets/report-template.html
#  - Structured JSON-lines logging with retention-based rotation
#  - Webhook notifications (Slack/Teams-compatible)
# Requires: PowerShell 5.1+ (no PS7 dependency)
# ============================================================

#Requires -Version 5.1

<#
.SYNOPSIS
    Monitors APT intelligence feeds and generates threat reports.
.DESCRIPTION
    This script fetches RSS/Atom feeds from cybersecurity sources,
    analyzes them for threat intelligence keywords and MITRE ATT&CK
    techniques, and generates comprehensive HTML and CSV reports.
    Deduplication, HTTP caching metadata and feed health history are
    persisted in a state file so consecutive runs don't need a manual
    previous CSV.
.PARAMETER ConfigPath
    Path to the JSON configuration file. Defaults to config.json in script directory.
.PARAMETER PreviousCsvPath
    Path to a previous CSV report to seed deduplication.
.PARAMETER SkipDeduplication
    Ignore the state file / previous CSV for this run (everything is treated as new).
.PARAMETER StatePath
    Path to the persistent state file. Defaults to ThreatRavenState.json in script directory.
.PARAMETER LogDir
    Directory for log files. Defaults to 'logs' in script directory.
.PARAMETER OutputDir
    Directory for output files. Defaults to script directory.
.PARAMETER ExportHealthReport
    Export feed health data to JSON file.
.PARAMETER QuietMode
    Suppress all console output (logs still written).
.PARAMETER NonInteractive
    Skip all interactive prompts (no prompts exist in v4; kept for compatibility).
.PARAMETER NoOpenReport
    Do not automatically open the HTML report after generation.
.EXAMPLE
    .\ThreatRaven.ps1
.EXAMPLE
    .\ThreatRaven.ps1 -PreviousCsvPath "C:\Reports\previous.csv" -ExportHealthReport
.EXAMPLE
    .\ThreatRaven.ps1 -ConfigPath "C:\Config\custom.json" -OutputDir "C:\Reports"
.EXAMPLE
    .\ThreatRaven.ps1 -NonInteractive -NoOpenReport -QuietMode
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath = "",
    [string]$PreviousCsvPath,
    [switch]$SkipDeduplication,
    [string]$StatePath = "",
    [string]$LogDir = "",
    [string]$OutputDir = "",
    [switch]$ExportHealthReport,
    [switch]$QuietMode,
    [switch]$NonInteractive,
    [switch]$NoOpenReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Resolve script root when invoked via -File (PSScriptRoot may be empty)
if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
    if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $PSScriptRoot = (Get-Location).Path
    }
}

# Apply defaults that depend on $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath = Join-Path $PSScriptRoot "config.json" }
if ([string]::IsNullOrWhiteSpace($LogDir))     { $LogDir = Join-Path $PSScriptRoot "logs" }
if ([string]::IsNullOrWhiteSpace($OutputDir))  { $OutputDir = $PSScriptRoot }
if ([string]::IsNullOrWhiteSpace($StatePath))  { $StatePath = Join-Path $PSScriptRoot "ThreatRavenState.json" }

# ============================================================
# CONSTANTS
# ============================================================
$script:SCRIPT_VERSION = '4.0'
$script:SECONDS_PER_DAY = 86400
$script:DEFAULT_MITRE_INITIAL_SHOW = 5
$script:DEFAULT_KEYWORD_TOP_N = 10
$script:LogLevel = 'Info'

# ============================================================
# TLS 1.2+ (Windows PowerShell 5.1 defaults to old protocols)
# ============================================================
try {
    $tls13 = [System.Net.SecurityProtocolType]'Tls13'
    [System.Net.ServicePointManager]::SecurityProtocol = $tls13 -bor [System.Net.SecurityProtocolType]::Tls12
}
catch {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

# ============================================================
# MODULE IMPORT
# ============================================================
$script:ModulePath = Join-Path $PSScriptRoot "FeedHelpers.psm1"
if (-not (Test-Path -LiteralPath $script:ModulePath)) {
    throw "Helper module not found at: $script:ModulePath"
}
Import-Module $script:ModulePath -Force -ErrorAction Stop

# ============================================================
# LOGGING
# ============================================================
$script:Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$script:ScriptDir = $PSScriptRoot

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$script:LogFile = Join-Path $LogDir "ThreatFeed_$script:Timestamp.log"

function Write-Log {
    <#
    .SYNOPSIS
        Writes a structured (JSON-lines) timestamped log entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Debug', 'Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $entry = [ordered]@{
        ts    = (Get-Date).ToString('o')
        level = $Level
        msg   = $Message
    }

    try {
        if ($script:LogFile) {
            ($entry | ConvertTo-Json -Compress) |
                Out-File -FilePath $script:LogFile -Append -Encoding UTF8
        }
    }
    catch {
        Write-Warning "Failed to write to log file: $($_.Exception.Message)"
    }

    if (-not $script:QuietMode) {
        if ($Level -eq 'Debug' -and $script:LogLevel -ne 'Debug') { return }
        $color = switch ($Level) {
            'Info'    { 'Cyan' }
            'Warning' { 'Yellow' }
            'Error'   { 'Red' }
            'Debug'   { 'DarkGray' }
        }
        Write-Host "[$($entry.ts)] [$Level] $Message" -ForegroundColor $color
    }
}

function Write-Console {
    <#
    .SYNOPSIS
        Console output that respects -QuietMode.
    #>
    param(
        [string]$Message = '',
        [string]$ForegroundColor = 'Gray'
    )
    if (-not $script:QuietMode) {
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
}

function Write-ProgressIfNotQuiet {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete
    )
    if (-not $script:QuietMode) {
        Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    }
}

# ============================================================
# MAIN SCRIPT
# ============================================================
try {
    Write-Log "=== ThreatRaven v$script:SCRIPT_VERSION ===" -Level Info
    Write-Log "by Diyar Abbas | diyar.jaafar@gmail.com | github.com/diyarit" -Level Info
    Write-Log "Script started at: $script:Timestamp" -Level Info

    # Load configuration (merges defaults, validates)
    $config = Initialize-Configuration -Path $ConfigPath
    $Settings = $config.Settings

    $script:VulnDays                  = [int]$Settings.VulnDays
    $script:ThrottleLimit             = [int]$Settings.ThrottleLimit
    $script:FeedTimeoutSeconds        = [int]$Settings.FeedTimeoutSeconds
    $script:MaxRetries                = [int]$Settings.MaxRetries
    $script:RetryBaseDelaySeconds     = [int]$Settings.RetryBaseDelaySeconds
    $script:LogLevel                  = [string]$Settings.LogLevel
    $script:ValidateCertificates      = [bool]$Settings.ValidateCertificates
    $script:ExportHealthEnabled       = $ExportHealthReport -or [bool]$Settings.ExportHealthReport
    $script:NvdEnabled                = [bool]$Settings.NvdEnabled
    $script:NvdApiKey                 = [string]$Settings.NvdApiKey
    $script:NvdMaxResults             = [int]$Settings.NvdMaxResults
    $script:NvdCacheHours             = [int]$Settings.NvdCacheHours
    $script:NvdKeywordFilter          = [bool]$Settings.NvdKeywordFilter
    $script:MinHostRequestIntervalMs  = [int]$Settings.MinHostRequestIntervalMs
    $script:GlobalTimeoutSeconds      = [int]$Settings.GlobalTimeoutSeconds
    $script:StateRetentionDays        = [int]$Settings.StateRetentionDays
    $script:StateMaxEntries           = [int]$Settings.StateMaxEntries
    $script:ReportHistoryDays         = [int]$Settings.ReportHistoryDays
    $script:LogRetentionDays          = [int]$Settings.LogRetentionDays
    $script:EnableConditionalRequests = [bool]$Settings.EnableConditionalRequests
    $script:WebhookEnabled            = [bool]$Settings.WebhookEnabled
    $script:WebhookUrl                = [string]$Settings.WebhookUrl

    Write-Log "Configuration loaded: $($config.Feeds.Count) feeds, $($config.Keywords.Count) keywords" -Level Info

    # Rotate old logs
    if (Test-Path -LiteralPath $LogDir) {
        $logCutoff = (Get-Date).AddDays(-$script:LogRetentionDays)
        Get-ChildItem -LiteralPath $LogDir -Filter 'ThreatFeed_*.log' -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $logCutoff } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }

    # Certificate validation: set once for the whole run (ServicePointManager is process-global)
    if ($script:ValidateCertificates) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }
    else {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }

    # ============================================================
    # PERSISTENT STATE
    # ============================================================
    $script:State = Initialize-ThreatRavenState -Path $StatePath `
        -RetentionDays $script:StateRetentionDays -MaxEntries $script:StateMaxEntries
    Write-Log "State loaded: $($script:State.Items.Count) known links" -Level Debug

    $ExistingLinks = [System.Collections.Concurrent.ConcurrentDictionary[string,bool]]::new([StringComparer]::OrdinalIgnoreCase)
    $StateSeenBefore = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    if (-not $SkipDeduplication) {
        foreach ($key in $script:State.Items.Keys) {
            $null = $StateSeenBefore.Add($key)
            $null = $ExistingLinks.TryAdd($key, $true)
        }
    }

    # Seed from a previous CSV (backward compatibility)
    if ($PreviousCsvPath -and (Test-Path -LiteralPath $PreviousCsvPath)) {
        Write-Log "Seeding deduplication from previous CSV: $PreviousCsvPath" -Level Info
        try {
            $previousRows = Import-Csv -Path $PreviousCsvPath -Encoding UTF8
            $nowStr = (Get-Date).ToString('o')
            foreach ($row in $previousRows) {
                if ([string]::IsNullOrWhiteSpace($row.Link)) { continue }
                $norm = ConvertTo-NormalizedUrl -Url $row.Link
                if ([string]::IsNullOrWhiteSpace($norm)) { continue }
                $null = $ExistingLinks.TryAdd($norm, $true)
                $null = $StateSeenBefore.Add($norm)
                if (-not $script:State.Items.ContainsKey($norm)) {
                    $mt = ''
                    if ($row.PSObject.Properties['MitreTechniques']) { $mt = $row.MitreTechniques }
                    $script:State.Items[$norm] = [PSCustomObject]@{
                        Normalized      = $norm
                        Date            = (ConvertTo-DateTime -InputObject ([string]$row.Date) -Fallback (Get-Date)).ToString('o')
                        Source          = [string]$row.Source
                        Title           = [string]$row.Title
                        Keywords        = [string]$row.Keywords
                        MitreTechniques = $mt
                        Link            = [string]$row.Link
                        FirstSeen       = $nowStr
                        LastSeen        = $nowStr
                    }
                }
            }
            Write-Log "Seeded $($previousRows.Count) rows from previous CSV" -Level Info
        }
        catch {
            Write-Log "Error reading previous CSV: $($_.Exception.Message)" -Level Warning
        }
    }

    # Pre-compile regex patterns
    Write-Log "Pre-compiling regex patterns..." -Level Debug
    $script:rxOpts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                     [System.Text.RegularExpressions.RegexOptions]::Compiled

    $script:CompiledKeywords = $config.Keywords | ForEach-Object {
        [System.Text.RegularExpressions.Regex]::new(
            "\b" + [System.Text.RegularExpressions.Regex]::Escape($_) + "\b",
            $script:rxOpts
        )
    }

    $script:CompiledMitre = @{}
    foreach ($tid in $config.MitreKeywords.PSObject.Properties.Name) {
        $tech = $config.MitreKeywords.$tid
        $patterns = $tech.Keywords | ForEach-Object {
            [System.Text.RegularExpressions.Regex]::new(
                "\b" + [System.Text.RegularExpressions.Regex]::Escape($_) + "\b",
                $script:rxOpts
            )
        }
        $script:CompiledMitre[$tid] = @{ Name = $tech.Name; Patterns = $patterns }
    }

    Write-Log "Compiled $($script:CompiledKeywords.Count) keyword patterns" -Level Debug
    Write-Log "Compiled $($script:CompiledMitre.Count) MITRE technique patterns" -Level Debug

    # Ensure output directory exists
    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        Write-Log "Created output directory: $OutputDir" -Level Info
    }

    # State and paths
    $CsvPath = Join-Path $OutputDir "APT_Report_$script:Timestamp.csv"
    $HtmlPath = Join-Path $OutputDir "APT_Report_$script:Timestamp.html"
    $HealthReportPath = Join-Path $OutputDir "FeedHealth_$script:Timestamp.json"
    $ConfigSnapshotPath = Join-Path $OutputDir "RunConfig_$script:Timestamp.json"

    $ResultsBag = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()
    $script:FeedHealth = [System.Collections.Concurrent.ConcurrentDictionary[string,PSObject]]::new()

    # Save run configuration for audit
    Save-RunConfiguration -Config $config -Path $ConfigSnapshotPath -StatePath $StatePath

    Write-Console "`n=== ThreatRaven v$script:SCRIPT_VERSION ===" -ForegroundColor Cyan
    Write-Console "by Diyar Abbas | diyar.jaafar@gmail.com | github.com/diyarit" -ForegroundColor DarkGray
    if (-not $SkipDeduplication) {
        Write-Console "Deduplicating against state file ($($script:State.Items.Count) known links)" -ForegroundColor Yellow
    }

    # Feed health tracking function
    function Update-FeedHealth {
        [CmdletBinding()]
        param(
            [string]$FeedUrl,
            [bool]$Success,
            [int]$ItemsProcessed = 0,
            [int]$MatchesFound = 0,
            [string]$ErrorMessage = "",
            [double]$DurationMs = 0
        )

        $hostName = ([System.Uri]$FeedUrl).Host
        $health = $null
        if (-not $script:FeedHealth.TryGetValue($FeedUrl, [ref]$health)) {
            $health = [PSCustomObject]@{
                FeedUrl       = $FeedUrl
                Host          = $hostName
                SuccessCount  = 0
                FailureCount  = 0
                TotalItems    = 0
                TotalMatches  = 0
                LastError     = ""
                LastChecked   = $null
                ResponseTimes = [System.Collections.Generic.List[double]]::new()
            }
            $null = $script:FeedHealth.TryAdd($FeedUrl, $health)
        }

        $health.LastChecked = Get-Date
        if ($DurationMs -gt 0) { $health.ResponseTimes.Add($DurationMs) }
        if ($Success) {
            $health.SuccessCount++
            $health.TotalItems += $ItemsProcessed
            $health.TotalMatches += $MatchesFound
        }
        else {
            $health.FailureCount++
            $health.LastError = $ErrorMessage
        }
    }

    # ============================================================
    # PARALLEL FEED FETCHING
    # ============================================================
    Write-Log "Starting feed scraping..." -Level Info
    Write-Log "Total Feeds: $($config.Feeds.Count) | Parallel workers: $script:ThrottleLimit" -Level Info

    $script:StartTime = Get-Date

    $RawMitreKeywords = @{}
    foreach ($tid in $config.MitreKeywords.PSObject.Properties.Name) {
        $RawMitreKeywords[$tid] = @{
            Name     = $config.MitreKeywords.$tid.Name
            Keywords = $config.MitreKeywords.$tid.Keywords
        }
    }

    $RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $script:ThrottleLimit)
    $RunspacePool.Open()
    $script:RunspacePoolOpen = $true

    $FeedScriptBlock = {
        param(
            [string]$Url,
            [string[]]$KeywordList,
            [hashtable]$RawMitre,
            $ExistingLinksRef,
            [int]$TimeoutSeconds,
            [int]$MaxRetryCount,
            [int]$RetryBaseSec,
            [string[]]$UserAgentList,
            [string]$ModulePath,
            [hashtable]$FeedCache,
            [bool]$UseConditionalRequests
        )

        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        Import-Module $ModulePath -Force -ErrorAction Stop | Out-Null

        # Compile regex locally (cannot serialize compiled regexes across runspaces)
        $localRxOpts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                       [System.Text.RegularExpressions.RegexOptions]::Compiled

        $localKwRegex = $KeywordList | ForEach-Object {
            [System.Text.RegularExpressions.Regex]::new(
                "\b" + [System.Text.RegularExpressions.Regex]::Escape($_) + "\b", $localRxOpts
            )
        }
        $kwNames = $KeywordList

        $localMitreRegex = @{}
        foreach ($tid in $RawMitre.Keys) {
            $localMitreRegex[$tid] = @{
                Name     = $RawMitre[$tid].Name
                Patterns = $RawMitre[$tid].Keywords | ForEach-Object {
                    [System.Text.RegularExpressions.Regex]::new(
                        "\b" + [System.Text.RegularExpressions.Regex]::Escape($_) + "\b", $localRxOpts
                    )
                }
            }
        }

        $localResults = [System.Collections.Generic.List[PSObject]]::new()
        $fetchSuccess = $false
        $permanentError = $false
        $unchanged = $false
        $saw429 = $false
        $rateLimitDelay = 0
        $lastError = ''
        $lastStatus = 0
        $feedHost = ([System.Uri]$Url).Scheme + '://' + ([System.Uri]$Url).Host
        $fetchStartTime = Get-Date
        $attempt = 0
        $webRequest = $null
        $maxAttempts = $MaxRetryCount

        while ($attempt -lt $maxAttempts -and -not $fetchSuccess -and -not $permanentError) {
            $attempt++
            foreach ($agent in $UserAgentList) {
                $headers = @{
                    "User-Agent"      = $agent
                    "Accept"          = "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"
                    "Accept-Language" = "en-US,en;q=0.9"
                    "Cache-Control"   = "no-cache"
                    "Referer"         = $feedHost
                }

                if ($UseConditionalRequests -and $null -ne $FeedCache) {
                    if ($FeedCache['Etag']) {
                        $headers['If-None-Match'] = [string]$FeedCache['Etag']
                    }
                    if ($FeedCache['LastModified']) {
                        $lm = ConvertTo-DateTime -InputObject ([string]$FeedCache['LastModified']) -Fallback ([DateTime]::MinValue)
                        if ($lm -gt [DateTime]::MinValue) {
                            $headers['If-Modified-Since'] = $lm.ToUniversalTime().ToString('r')
                        }
                    }
                }

                $statusCode = 0
                $errMsg = ''
                $iwrParams = @{
                    Uri            = $Url
                    TimeoutSec     = $TimeoutSeconds
                    UseBasicParsing = $true
                    Headers        = $headers
                }
                if ($PSVersionTable.PSVersion.Major -ge 7) {
                    $iwrParams['SkipHttpErrorCheck'] = $true
                }

                try {
                    $webRequest = Invoke-WebRequest @iwrParams
                    $statusCode = [int]$webRequest.StatusCode
                }
                catch {
                    $errMsg = $_.Exception.Message
                    $resp = $_.Exception.Response
                    if ($null -ne $resp -and $null -ne $resp.StatusCode) {
                        $statusCode = [int]$resp.StatusCode
                    }
                    elseif ($errMsg -match '\((3\d\d|4\d\d|5\d\d)\)') {
                        $statusCode = [int]$Matches[1]
                    }
                }

                $respForHeaders = if ($null -ne $webRequest) { $webRequest } else { $resp }

                if ($statusCode -eq 304) {
                    $unchanged = $true
                    $fetchSuccess = $true
                    break
                }
                if ($statusCode -eq 400 -or $statusCode -eq 401 -or $statusCode -eq 404 -or $statusCode -eq 410) {
                    $permanentError = $true
                    $lastStatus = $statusCode
                    $lastError = $errMsg
                    break
                }
                if ($statusCode -eq 429) {
                    $saw429 = $true
                    $lastStatus = $statusCode
                    if ($errMsg) { $lastError = $errMsg }

                    # Honor Retry-After when the server provides it (seconds or HTTP-date)
                    $raRaw = $null
                    if ($null -ne $respForHeaders) {
                        $raRaw = Get-WebResponseHeader -Response $respForHeaders -Name 'Retry-After'
                    }
                    if ($raRaw) {
                        $raInt = 0
                        if ([int]::TryParse([string]$raRaw, [ref]$raInt) -and $raInt -gt 0) {
                            $rateLimitDelay = [Math]::Min($raInt, 60)
                        }
                        else {
                            $raDate = ConvertTo-DateTime -InputObject ([string]$raRaw) -Fallback ([DateTime]::MinValue)
                            if ($raDate -gt [DateTime]::MinValue) {
                                $waitSec = [int](($raDate - (Get-Date)).TotalSeconds)
                                $rateLimitDelay = [Math]::Min([Math]::Max(1, $waitSec), 60)
                            }
                        }
                    }
                    if ($rateLimitDelay -le 0) { $rateLimitDelay = 5 }

                    # Rate limits are per-IP; switching user agents won't help.
                    break
                }
                if ($statusCode -ge 200 -and $statusCode -lt 300) {
                    $fetchSuccess = $true
                    break
                }
                $lastStatus = $statusCode
                if ($errMsg) { $lastError = $errMsg }
            }

            if ($permanentError -or $fetchSuccess) { break }

            if ($saw429 -and $maxAttempts -eq $MaxRetryCount) {
                $maxAttempts = $MaxRetryCount + 2
            }

            if ($attempt -lt $maxAttempts) {
                if ($rateLimitDelay -gt 0) {
                    Start-Sleep -Seconds $rateLimitDelay
                    $rateLimitDelay = 0
                }
                else {
                    $delay = $RetryBaseSec * [Math]::Pow(2, $attempt - 1)
                    $jitter = Get-Random -Minimum 0 -Maximum ([Math]::Max(1, [int]($delay / 2)))
                    Start-Sleep -Seconds ($delay + $jitter)
                }
            }
        }

        $fetchDuration = ((Get-Date) - $fetchStartTime).TotalMilliseconds

        $errorResult = [PSCustomObject]@{
            Url             = $Url
            Results         = $localResults
            Error           = $null
            Warning         = $null
            Unchanged       = $unchanged
            MatchCount      = 0
            DupCount        = 0
            ItemsProcessed  = 0
            FetchDurationMs = $fetchDuration
            Cache           = $FeedCache
        }

        if ($unchanged) {
            $errorResult.Warning = 'Unchanged (conditional request)'
            return $errorResult
        }

        if (-not $fetchSuccess) {
            if ($lastStatus -eq 429) {
                $errorResult.Error = 'HTTP 429 (rate limited)'
            }
            elseif ($lastStatus -gt 0) { $errorResult.Error = "HTTP $lastStatus" }
            elseif ($lastError)        { $errorResult.Error = $lastError }
            else                       { $errorResult.Error = 'Fetch failed' }
            return $errorResult
        }

        # Persist ETag/Last-Modified for conditional requests next run
        if ($UseConditionalRequests -and $null -ne $FeedCache) {
            try {
                $etag = Get-WebResponseHeader -Response $webRequest -Name 'ETag'
                $lastMod = Get-WebResponseHeader -Response $webRequest -Name 'Last-Modified'
                if ($etag)    { $FeedCache['Etag'] = $etag }
                if ($lastMod) { $FeedCache['LastModified'] = $lastMod }
                $FeedCache['LastFetch'] = (Get-Date).ToString('o')
            }
            catch { }
        }

        # Secure XML parsing (module handles DTD/size hardening and cleanup)
        $parsed = ConvertFrom-FeedContent -Content $webRequest.Content
        if ($parsed.Error) {
            $errorResult.Error = $parsed.Error
            return $errorResult
        }

        $items = @($parsed.Items)
        if ($items.Count -eq 0) {
            $errorResult.Warning = 'No items'
            return $errorResult
        }

        $matchCount = 0
        $dupCount = 0
        $itemsProcessed = 0

        foreach ($item in $items) {
            $itemsProcessed++
            $fullText = Get-AllTextContent -Item $item
            if ([string]::IsNullOrWhiteSpace($fullText)) { continue }

            $matchedKeywords = [System.Collections.Generic.List[string]]::new()
            for ($ki = 0; $ki -lt $localKwRegex.Count; $ki++) {
                if ($localKwRegex[$ki].IsMatch($fullText)) {
                    $matchedKeywords.Add($kwNames[$ki])
                }
            }
            if ($matchedKeywords.Count -eq 0) { continue }

            $itemTitle = Get-FeedItemTitle -Item $item
            $itemLink = Get-ItemLink -Item $item -FeedUrl $Url
            if ([string]::IsNullOrWhiteSpace($itemLink)) { continue }

            # Never emit non-http(s) links into the report
            if (-not (Test-UrlSafety -Url $itemLink)) { continue }

            $normLink = ConvertTo-NormalizedUrl -Url $itemLink
            if ([string]::IsNullOrWhiteSpace($normLink)) { continue }

            if ($ExistingLinksRef.ContainsKey($normLink)) { $dupCount++; continue }

            $matchCount++
            $itemDate = Get-FeedItemDate -Item $item

            $detected = [System.Collections.Generic.List[string]]::new()
            foreach ($tid in $localMitreRegex.Keys) {
                $entry = $localMitreRegex[$tid]
                foreach ($rx in $entry.Patterns) {
                    if ($rx.IsMatch($fullText)) { $detected.Add("$tid - $($entry.Name)"); break }
                }
            }
            $mitreString = if ($detected.Count -gt 0) { ($detected | Sort-Object -Unique) -join '; ' } else { '' }

            $localResults.Add([PSCustomObject]@{
                Date            = $itemDate
                Source          = $Url
                Title           = $itemTitle
                Keywords        = (($matchedKeywords | Sort-Object -Unique) -join ', ')
                MitreTechniques = $mitreString
                Link            = $itemLink
                Normalized      = $normLink
                IsNew           = $false
            })
        }

        return [PSCustomObject]@{
            Url             = $Url
            Results         = $localResults
            Error           = $null
            Warning         = $null
            Unchanged       = $false
            MatchCount      = $matchCount
            DupCount        = $dupCount
            ItemsProcessed  = $itemsProcessed
            FetchDurationMs = $fetchDuration
            Cache           = $FeedCache
        }
    }

    # Dispatch runspaces
    $RunspaceHandles = [System.Collections.Generic.List[PSObject]]::new()
    $TotalFeeds = $config.Feeds.Count
    $CurrentFeed = 0
    $script:LastHostDispatch = @{}

    foreach ($url in $config.Feeds) {
        $CurrentFeed++

        if (-not (Test-UrlSafety -Url $url -AllowedPatterns $config.AllowedUrlPatterns)) {
            Write-Log "Skipping invalid URL: $url" -Level Warning
            continue
        }

        # Per-host request pacing (helps avoid rate limiting from the same domain)
        if ($script:MinHostRequestIntervalMs -gt 0) {
            $hostKey = ([System.Uri]$url).Host
            $lastDispatch = $script:LastHostDispatch[$hostKey]
            if ($null -ne $lastDispatch) {
                $elapsedMs = ([DateTime]::UtcNow - $lastDispatch).TotalMilliseconds
                if ($elapsedMs -lt $script:MinHostRequestIntervalMs) {
                    Start-Sleep -Milliseconds ($script:MinHostRequestIntervalMs - $elapsedMs)
                }
            }
            $script:LastHostDispatch[$hostKey] = [DateTime]::UtcNow
        }

        $feedCacheEntry = @{}
        if ($script:State.FeedCache.ContainsKey($url)) {
            $cachedEntry = $script:State.FeedCache[$url]
            foreach ($cp in $cachedEntry.PSObject.Properties) {
                $feedCacheEntry[$cp.Name] = $cp.Value
            }
        }

        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.RunspacePool = $RunspacePool

        $null = $ps.AddScript($FeedScriptBlock).AddParameters(@{
            Url                     = $url
            KeywordList             = $config.Keywords
            RawMitre                = $RawMitreKeywords
            ExistingLinksRef        = $ExistingLinks
            TimeoutSeconds          = $script:FeedTimeoutSeconds
            MaxRetryCount           = $script:MaxRetries
            RetryBaseSec            = $script:RetryBaseDelaySeconds
            UserAgentList           = $config.UserAgents
            ModulePath              = $script:ModulePath
            FeedCache               = $feedCacheEntry
            UseConditionalRequests  = $script:EnableConditionalRequests
        })

        $handle = $ps.BeginInvoke()
        $RunspaceHandles.Add([PSCustomObject]@{
            PowerShell = $ps
            Handle     = $handle
            Url        = $url
            Index      = $CurrentFeed
            StartTime  = Get-Date
            Cache      = $feedCacheEntry
        })
    }

    # Collect results with a global deadline (poll IsCompleted; Stop() stragglers)
    $NewLinksCount = 0
    $DuplicatesSkipped = 0
    $Completed = 0
    $TotalFetchTimeMs = 0.0
    $DispatchedFeeds = $RunspaceHandles.Count

    $deadline = [DateTime]::UtcNow.AddSeconds($script:GlobalTimeoutSeconds)
    $pending = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($h in $RunspaceHandles) { $pending.Add($h) }
    $completedJobs = [System.Collections.Generic.List[PSObject]]::new()

    Write-Console ""
    while ($pending.Count -gt 0) {
        if ([DateTime]::UtcNow -ge $deadline) {
            foreach ($job in $pending.ToArray()) {
                Write-Log "Global timeout waiting for feed: $($job.Url)" -Level Warning
                Update-FeedHealth -FeedUrl $job.Url -Success $false -ErrorMessage 'Global timeout'
                try { $job.PowerShell.Stop() } catch { }
                try { $job.PowerShell.Dispose() } catch { }
            }
            $pending.Clear()
            break
        }

        $found = $false
        foreach ($job in $pending.ToArray()) {
            if ($job.Handle.IsCompleted) {
                $completedJobs.Add($job)
                $null = $pending.Remove($job)
                $found = $true
            }
        }
        if (-not $found) { Start-Sleep -Milliseconds 200 }
    }

    foreach ($job in ($completedJobs | Sort-Object { $_.Index })) {
        $Completed++
        $pct = if ($DispatchedFeeds -gt 0) { [math]::Round(($Completed / $DispatchedFeeds) * 100) } else { 100 }
        Write-ProgressIfNotQuiet -Activity "Scanning RSS Feeds" -Status "Completed $Completed of $DispatchedFeeds ($pct%)" -PercentComplete $pct

        $feedName = ([System.Uri]$job.Url).Host
        Write-Console "[$Completed/$DispatchedFeeds] $feedName" -ForegroundColor Gray

        try {
            $output = $job.PowerShell.EndInvoke($job.Handle)
            $result = @($output)[0]

            if ($null -eq $result) {
                Write-Console " - No result returned" -ForegroundColor DarkYellow
                Update-FeedHealth -FeedUrl $job.Url -Success $false -ErrorMessage 'Feed returned no result'
            }
            else {
                if ($result.Cache -is [hashtable] -and $result.Cache.Count -gt 0) {
                    $script:State.FeedCache[$job.Url] = $result.Cache
                }

                $success = [string]::IsNullOrEmpty($result.Error)
                Update-FeedHealth -FeedUrl $job.Url -Success $success `
                    -ItemsProcessed $result.ItemsProcessed -MatchesFound $result.MatchCount `
                    -ErrorMessage $result.Error -DurationMs ([double]$result.FetchDurationMs)
                $TotalFetchTimeMs += [double]$result.FetchDurationMs
                $DuplicatesSkipped += $result.DupCount

                if ($result.Error) {
                    Write-Console " - $($result.Error)" -ForegroundColor DarkYellow
                }
                elseif ($result.Unchanged) {
                    Write-Console " - Unchanged (cached)" -ForegroundColor DarkGray
                }
                elseif ($result.Warning) {
                    Write-Console " - $($result.Warning)" -ForegroundColor DarkGray
                }
                elseif ($result.MatchCount -gt 0) {
                    $msg = " - Found $($result.MatchCount) new"
                    if ($result.DupCount -gt 0) { $msg += " ($($result.DupCount) duplicates skipped)" }
                    Write-Console $msg -ForegroundColor Green
                }
                elseif ($result.DupCount -gt 0) {
                    Write-Console " - No new matches ($($result.DupCount) duplicates skipped)" -ForegroundColor DarkGray
                }
                else {
                    Write-Console " - No matches" -ForegroundColor DarkGray
                }

                foreach ($item in $result.Results) {
                    $norm = [string]$item.Normalized
                    if ([string]::IsNullOrWhiteSpace($norm)) {
                        $norm = ConvertTo-NormalizedUrl -Url $item.Link
                    }
                    if ([string]::IsNullOrWhiteSpace($norm)) { continue }

                    if ($ExistingLinks.ContainsKey($norm)) {
                        $DuplicatesSkipped++
                        continue
                    }
                    $null = $ExistingLinks.TryAdd($norm, $true)

                    $isNew = -not $StateSeenBefore.Contains($norm)
                    if ($isNew) { $NewLinksCount++ }

                    $nowStr = (Get-Date).ToString('o')
                    $itemDateStr = if ($item.Date -is [DateTime]) { $item.Date.ToString('o') } else { [string]$item.Date }
                    if ($script:State.Items.ContainsKey($norm)) {
                        $script:State.Items[$norm].LastSeen = $nowStr
                    }
                    else {
                        $script:State.Items[$norm] = [PSCustomObject]@{
                            Normalized      = $norm
                            Date            = $itemDateStr
                            Source          = $item.Source
                            Title           = $item.Title
                            Keywords        = $item.Keywords
                            MitreTechniques = $item.MitreTechniques
                            Link            = $item.Link
                            FirstSeen       = $nowStr
                            LastSeen        = $nowStr
                        }
                    }

                    $ResultsBag.Add([PSCustomObject]@{
                        Date            = $item.Date
                        Source          = $item.Source
                        Title           = $item.Title
                        Keywords        = $item.Keywords
                        MitreTechniques = $item.MitreTechniques
                        Link            = $item.Link
                        Normalized      = $norm
                        IsNew           = $isNew
                    })
                }
            }
        }
        catch {
            Write-Console " - Runner error: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log "Runner error for $($job.Url): $($_.Exception.Message)" -Level Error
            Update-FeedHealth -FeedUrl $job.Url -Success $false -ErrorMessage $_.Exception.Message
        }
        finally {
            try { $job.PowerShell.Dispose() } catch { }
        }
    }

    if ($script:RunspacePoolOpen) {
        $RunspacePool.Close()
        $RunspacePool.Dispose()
        $script:RunspacePoolOpen = $false
    }
    Write-ProgressIfNotQuiet -Activity "Scanning RSS Feeds" -Status "Complete" -PercentComplete 100

    # Export health report if requested
    if ($script:ExportHealthEnabled) {
        Export-FeedHealthReport -FeedHealth $script:FeedHealth -Path $HealthReportPath
        Write-Log "Feed health report exported: $HealthReportPath" -Level Info
    }

    # Feed health summary
    $healthReport = Get-FeedHealthReport -FeedHealth $script:FeedHealth
    Write-Log "=== Feed Health Summary ===" -Level Info
    Write-Log "Healthy: $($healthReport.Healthy) | Degraded: $($healthReport.Degraded) | Unhealthy: $($healthReport.Unhealthy)" -Level Info

    foreach ($unhealthyFeed in $healthReport.UnhealthyFeeds) {
        Write-Log "$($unhealthyFeed.Status): $($unhealthyFeed.Host) ($($unhealthyFeed.Feed)) - $($unhealthyFeed.LastError)" -Level Warning
    }

    # Merge and sort results
    Write-Log "Processing results..." -Level Info
    Write-Log "New matches found: $NewLinksCount" -Level Info
    Write-Log "Duplicates skipped: $DuplicatesSkipped" -Level Info

    $AllResultsList = [System.Collections.Generic.List[PSObject]]::new()
    $runKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $ResultsBag) {
        $null = $runKeys.Add([string]$item.Normalized)
        $AllResultsList.Add($item)
    }

    # Include recently-seen history from the state file (marked as "seen")
    if (-not $SkipDeduplication -and $script:ReportHistoryDays -gt 0) {
        $historyItems = @(Get-ThreatRavenHistoryItems -State $script:State -Days $script:ReportHistoryDays)
        foreach ($h in $historyItems) {
            $norm = [string]$h.Normalized
            if ([string]::IsNullOrWhiteSpace($norm)) {
                $norm = ConvertTo-NormalizedUrl -Url $h.Link
            }
            if ([string]::IsNullOrWhiteSpace($norm)) { continue }
            if (-not $runKeys.Add($norm)) { continue }

            $AllResultsList.Add([PSCustomObject]@{
                Date            = ConvertTo-DateTime -InputObject ([string]$h.Date) -Fallback (Get-Date)
                Source          = $h.Source
                Title           = $h.Title
                Keywords        = $h.Keywords
                MitreTechniques = $h.MitreTechniques
                Link            = $h.Link
                IsNew           = $false
            })
        }
    }

    $AllResultsForCSV = @($AllResultsList | Sort-Object {
        if ($_.Date -is [DateTime]) {
            $_.Date
        }
        else {
            ConvertTo-DateTime -InputObject ([string]$_.Date) -Fallback ([DateTime]::new(2000, 1, 1))
        }
    } -Descending)

    # Export CSV
    $AllResultsForCSV | Select-Object Date, Source, Title, Keywords, MitreTechniques, Link |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

    Write-Log "CSV exported to: $CsvPath" -Level Info

    # Statistics
    $KeywordStats = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($result in $AllResultsForCSV) {
        if ($result.Keywords) {
            foreach ($kw in ($result.Keywords -split ',\s*')) {
                $kw = $kw.Trim()
                if ($kw -ne '') {
                    if ($KeywordStats.ContainsKey($kw)) { $KeywordStats[$kw]++ } else { $KeywordStats[$kw] = 1 }
                }
            }
        }
    }

    $MitreStats = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($result in $AllResultsForCSV) {
        if ($result.MitreTechniques) {
            foreach ($tech in ($result.MitreTechniques -split ';\s*')) {
                $tech = $tech.Trim()
                if ($tech -ne '') {
                    if ($MitreStats.ContainsKey($tech)) { $MitreStats[$tech]++ } else { $MitreStats[$tech] = 1 }
                }
            }
        }
    }

    # ============================================================
    # SERVER-SIDE NVD CVE FETCH (paginated, cached, rate-limit aware)
    # ============================================================
    $jsVulnData = '[]'
    $jsVulnError = ''
    $vulnTruncated = 'false'

    if ($script:NvdEnabled) {
        try {
            $nvd = Get-NvdCves -Days $script:VulnDays -ApiKey $script:NvdApiKey `
                -MaxResults $script:NvdMaxResults -Keywords @($config.Keywords) `
                -KeywordFilter $script:NvdKeywordFilter -State $script:State `
                -CacheHours $script:NvdCacheHours

            $vulnParts = [System.Text.StringBuilder]::new()
            $vulnParts.Append('[') | Out-Null
            $firstVuln = $true
            foreach ($cve in $nvd.Cves) {
                if (-not $firstVuln) { $vulnParts.Append(',') | Out-Null }
                $vId    = ConvertTo-JavaScriptString -Text ([string]$cve.id)
                $vPub   = ConvertTo-JavaScriptString -Text ([string]$cve.published)
                $vSev   = ConvertTo-JavaScriptString -Text ([string]$cve.severity)
                $vDesc  = ConvertTo-JavaScriptString -Text ([string]$cve.description)
                $vScore = [math]::Round([double]$cve.score, 1)
                $vulnParts.Append("{id:`"$vId`",published:`"$vPub`",severity:`"$vSev`",score:$vScore,description:`"$vDesc`"}") | Out-Null
                $firstVuln = $false
            }
            $vulnParts.Append(']') | Out-Null
            $jsVulnData = $vulnParts.ToString()
            $vulnTruncated = if ($nvd.Truncated) { 'true' } else { 'false' }
            Write-Log "NVD: loaded $($nvd.Cves.Count) CVEs for the last $script:VulnDays days" -Level Info
        }
        catch {
            $jsVulnError = $_.Exception.Message
            Write-Log "NVD fetch failed: $($_.Exception.Message)" -Level Warning
        }
    }
    else {
        Write-Log "NVD integration disabled (NvdEnabled=false)" -Level Debug
    }

    $TotalDuration = ((Get-Date) - $script:StartTime).TotalSeconds

    # ============================================================
    # BUILD JAVASCRIPT DATA (all values JS-escaped server-side)
    # ============================================================
    $jsDataItems = [System.Text.StringBuilder]::new()
    $firstItem = $true

    foreach ($item in $AllResultsForCSV) {
        $itemDate = if ($item.Date -is [DateTime]) {
            $item.Date
        }
        else {
            ConvertTo-DateTime -InputObject ([string]$item.Date) -Fallback (Get-Date)
        }

        $dateStr = $itemDate.ToString("yyyy-MM-dd HH:mm")
        $timestamp = [Math]::Floor(([DateTimeOffset]$itemDate).ToUnixTimeSeconds())

        $jsTitle    = ConvertTo-JavaScriptString -Text "$($item.Title)"
        $jsSource   = ConvertTo-JavaScriptString -Text "$($item.Source)"
        $jsKeywords = ConvertTo-JavaScriptString -Text "$($item.Keywords)"
        $jsMitre    = ConvertTo-JavaScriptString -Text "$($item.MitreTechniques)"
        $jsLink     = ConvertTo-JavaScriptString -Text "$($item.Link)"
        $isNew      = if ($item.IsNew) { 'true' } else { 'false' }

        if (-not $firstItem) { $null = $jsDataItems.Append(',') }
        $null = $jsDataItems.Append("{ts:$timestamp,dt:`"$dateStr`",src:`"$jsSource`",ttl:`"$jsTitle`",kw:`"$jsKeywords`",mitre:`"$jsMitre`",lnk:`"$jsLink`",new:$isNew}")
        $firstItem = $false
    }

    $jsArray = "[" + $jsDataItems.ToString() + "]"

    # Keyword stats object
    $kwParts = [System.Text.StringBuilder]::new()
    $kwParts.Append('{') | Out-Null
    $firstKw = $true
    foreach ($kw in $KeywordStats.GetEnumerator()) {
        if (-not $firstKw) { $kwParts.Append(',') | Out-Null }
        $escapedKey = ConvertTo-JavaScriptString -Text $kw.Key
        $kwParts.Append("`"$escapedKey`":$($kw.Value)") | Out-Null
        $firstKw = $false
    }
    $kwParts.Append('}') | Out-Null
    $jsKeywordsObj = $kwParts.ToString()

    # MITRE stats object
    $mitreParts = [System.Text.StringBuilder]::new()
    $mitreParts.Append('{') | Out-Null
    $firstMitre = $true
    foreach ($tech in $MitreStats.GetEnumerator()) {
        if (-not $firstMitre) { $mitreParts.Append(',') | Out-Null }
        $escapedKey = ConvertTo-JavaScriptString -Text $tech.Key
        $mitreParts.Append("`"$escapedKey`":$($tech.Value)") | Out-Null
        $firstMitre = $false
    }
    $mitreParts.Append('}') | Out-Null
    $jsMitreStats = $mitreParts.ToString()

    # Feed health array
    $healthParts = [System.Text.StringBuilder]::new()
    $healthParts.Append('[') | Out-Null
    $firstHealth = $true
    foreach ($entry in $script:FeedHealth.GetEnumerator()) {
        if (-not $firstHealth) { $healthParts.Append(',') | Out-Null }
        $hHost = ConvertTo-JavaScriptString -Text $entry.Value.Host
        $hStatus = if ($entry.Value.FailureCount -eq 0) { "healthy" }
                   elseif ($entry.Value.FailureCount -gt 2) { "degraded" }
                   else { "unhealthy" }
        $hLastErr = ConvertTo-JavaScriptString -Text $entry.Value.LastError
        $hLastChecked = if ($entry.Value.LastChecked) { $entry.Value.LastChecked.ToString('yyyy-MM-dd HH:mm') } else { "" }
        $null = $healthParts.Append("{host:`"$hHost`",status:`"$hStatus`",ok:$($entry.Value.SuccessCount),fail:$($entry.Value.FailureCount),items:$($entry.Value.TotalItems),matches:$($entry.Value.TotalMatches),err:`"$hLastErr`",checked:`"$hLastChecked`"}")
        $firstHealth = $false
    }
    $healthParts.Append(']') | Out-Null
    $jsFeedHealth = $healthParts.ToString()

    # ============================================================
    # HTML REPORT (external template + CSP nonce)
    # ============================================================
    Write-Console "`nGenerating HTML report..." -ForegroundColor Cyan

    $templatePath = Join-Path $PSScriptRoot "assets\report-template.html"
    if (-not (Test-Path -LiteralPath $templatePath)) {
        throw "Report template not found at: $templatePath"
    }
    $template = Get-Content -LiteralPath $templatePath -Raw -Encoding UTF8

    $nonceChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $cspNonce = -join (1..32 | ForEach-Object { $nonceChars[(Get-Random -Maximum $nonceChars.Length)] })

    $HtmlContent = $template.Replace('{{CSP_NONCE}}', $cspNonce)
    $HtmlContent = $HtmlContent.Replace('{{TOTAL_COUNT}}', [string]$AllResultsForCSV.Count)
    $HtmlContent = $HtmlContent.Replace('{{NEW_COUNT}}', [string]$NewLinksCount)
    $HtmlContent = $HtmlContent.Replace('{{DISPLAYED_COUNT}}', [string]$AllResultsForCSV.Count)
    $HtmlContent = $HtmlContent.Replace('{{MITRE_STAT_COUNT}}', [string]$MitreStats.Count)
    $HtmlContent = $HtmlContent.Replace('{{FEEDS_COUNT}}', [string]$TotalFeeds)
    $HtmlContent = $HtmlContent.Replace('{{TIME_SECONDS}}', [string][math]::Round($TotalDuration, 1))
    $HtmlContent = $HtmlContent.Replace('{{DATA_ITEMS}}', $jsArray)
    $HtmlContent = $HtmlContent.Replace('{{KEYWORD_STATS}}', $jsKeywordsObj)
    $HtmlContent = $HtmlContent.Replace('{{MITRE_STATS}}', $jsMitreStats)
    $HtmlContent = $HtmlContent.Replace('{{FEED_HEALTH}}', $jsFeedHealth)
    $HtmlContent = $HtmlContent.Replace('{{VULN_DATA}}', $jsVulnData)
    $HtmlContent = $HtmlContent.Replace('{{VULN_ERROR}}', (ConvertTo-JavaScriptString -Text $jsVulnError))
    $HtmlContent = $HtmlContent.Replace('{{VULN_TRUNCATED}}', $vulnTruncated)
    $HtmlContent = $HtmlContent.Replace('{{MITRE_INITIAL_SHOW}}', [string]$script:DEFAULT_MITRE_INITIAL_SHOW)
    $HtmlContent = $HtmlContent.Replace('{{KEYWORD_TOP_N}}', [string]$script:DEFAULT_KEYWORD_TOP_N)
    $HtmlContent = $HtmlContent.Replace('{{VULN_DAYS}}', [string]$script:VulnDays)
    $HtmlContent = $HtmlContent.Replace('{{SCRIPT_VERSION}}', $script:SCRIPT_VERSION)

    [System.IO.File]::WriteAllText($HtmlPath, $HtmlContent, [System.Text.UTF8Encoding]::new($false))

    # Copy local Chart.js library alongside report
    $libSource = Join-Path $PSScriptRoot "lib"
    $libDest = Join-Path $OutputDir "lib"
    if ((Test-Path -LiteralPath $libSource) -and $OutputDir -ne $PSScriptRoot) {
        if (-not (Test-Path -LiteralPath $libDest)) { New-Item -ItemType Directory -Path $libDest -Force | Out-Null }
        Copy-Item (Join-Path $libSource "chart.min.js") $libDest -Force
    }

    # Copy logo alongside report
    $logoSrc = Join-Path $PSScriptRoot "assets\logo.png"
    $logoDestDir = Join-Path $OutputDir "assets"
    if ((Test-Path -LiteralPath $logoSrc) -and $OutputDir -ne $PSScriptRoot) {
        if (-not (Test-Path -LiteralPath $logoDestDir)) { New-Item -ItemType Directory -Path $logoDestDir -Force | Out-Null }
        Copy-Item $logoSrc $logoDestDir -Force
    }

    # ============================================================
    # PERSIST STATE, NOTIFY, SUMMARY
    # ============================================================
    try {
        $script:State.HealthHistory += [PSCustomObject]@{
            Timestamp     = (Get-Date).ToString('o')
            Healthy       = $healthReport.Healthy
            Degraded      = $healthReport.Degraded
            Unhealthy     = $healthReport.Unhealthy
            TotalSuccess  = $healthReport.TotalSuccess
            TotalFailures = $healthReport.TotalFailures
        }
        Save-ThreatRavenState -State $script:State -Path $StatePath `
            -RetentionDays $script:StateRetentionDays -MaxEntries $script:StateMaxEntries
        Write-Log "State saved: $StatePath ($($script:State.Items.Count) known links)" -Level Debug
    }
    catch {
        Write-Log "Failed to save state file: $($_.Exception.Message)" -Level Warning
    }

    if ($script:WebhookEnabled -and $script:WebhookUrl) {
        Send-WebhookNotification -Url $script:WebhookUrl -NewCount $NewLinksCount `
            -TotalCount $AllResultsForCSV.Count -FeedCount $TotalFeeds `
            -DurationSeconds $TotalDuration -ReportPath $HtmlPath
    }

    Write-Log "HTML report generated: $HtmlPath" -Level Info
    Write-Console "[OK] Report generated successfully!" -ForegroundColor Green
    Write-Console "CSV: $CsvPath" -ForegroundColor Cyan
    Write-Console "HTML: $HtmlPath" -ForegroundColor Cyan
    Write-Console "Log: $script:LogFile" -ForegroundColor Cyan
    if ($script:ExportHealthEnabled) {
        Write-Console "Health Report: $HealthReportPath" -ForegroundColor Cyan
    }
    Write-Console "Config Snapshot: $ConfigSnapshotPath" -ForegroundColor Cyan
    Write-Console "State: $StatePath" -ForegroundColor Cyan
    Write-Console "`nSummary:" -ForegroundColor Yellow
    Write-Console "  New links found:    $NewLinksCount" -ForegroundColor Green
    Write-Console "  Duplicates skipped: $DuplicatesSkipped" -ForegroundColor Yellow
    Write-Console "  Total in report:    $($AllResultsForCSV.Count)" -ForegroundColor Cyan
    Write-Console "  MITRE Techniques:   $($MitreStats.Count)" -ForegroundColor Magenta
    Write-Console "  Processing Time:    $([math]::Round($TotalDuration, 2))s" -ForegroundColor Cyan
    if (-not $NoOpenReport) {
        Write-Console "`nOpening HTML report..." -ForegroundColor Yellow
        if ($PSCmdlet.ShouldProcess($HtmlPath, 'Open HTML report in default browser')) {
            Start-Process $HtmlPath
        }
    }
    else {
        Write-Console "`nHTML report ready: $HtmlPath" -ForegroundColor Yellow
    }
}
catch {
    Write-Log "Critical error: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error

    if ($script:RunspacePoolOpen -and $script:FeedHealth) {
        try {
            $RunspacePool.Close()
            $RunspacePool.Dispose()
        }
        catch { }
        $script:RunspacePoolOpen = $false
    }

    # Best-effort state save so seen links aren't lost on partial failures
    if ($script:State) {
        try {
            Save-ThreatRavenState -State $script:State -Path $StatePath `
                -RetentionDays $script:StateRetentionDays -MaxEntries $script:StateMaxEntries
        }
        catch { }
    }
    throw
}
