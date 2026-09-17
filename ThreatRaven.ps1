# ============================================================
# ThreatRaven.ps1 - APT Intelligence Feed Monitor
# Version: 5.0
#
# v5.0 changes:
#  - Fetching moved to HttpClient (FeedHelpers): gzip on PS 5.1, hard
#    response-size cap, bounded retry budget, UA rotation only on 403/406,
#    DNS/TLS failures not retried, identical behaviour on PS 5.1 and 7+
#  - Regexes compiled once and shared with workers by reference (was ~50k
#    IL compilations per run); dedupe runs before matching; module imported
#    once per runspace via InitialSessionState
#  - Results processed as feeds complete (live progress, no idle wait);
#    redundant dispatch-time host sleep removed (request-time gate stays)
#  - All dates UTC; report shows local time with the offset in the footer
#  - ETag/Last-Modified only persisted after a feed was parsed successfully
#  - Items without a resolvable link are skipped (no more collapse onto the
#    feed URL); explicit ATT&CK IDs in text are matched; configurable
#    minimum keyword hits per technique
#  - CVE IDs extracted from articles; CISA KEV + FIRST EPSS enrichment for
#    both articles and the NVD table; CVSS 4.0 support
#  - Feed health status uses run history (degraded is reachable)
#  - Feeds may be {Url, Name, Category} objects; reports show names
#  - Report data embedded as JSON (no hand-rolled JS string escaping);
#    template fixes (legend, sort toggle, light theme, filtered sources)
#  - Secrets: THREATRAVEN_NVD_API_KEY / THREATRAVEN_WEBHOOK_URL env vars,
#    HTTPS-only webhook, report path no longer sent to the webhook
#  - LogLevel honoured for all console levels; lock file deleted on close
# Requires: PowerShell 5.1+ (no PS7 dependency)
# ============================================================

#Requires -Version 5.1

<#
.SYNOPSIS
    Monitors APT intelligence feeds and generates threat reports.
.DESCRIPTION
    Fetches RSS/Atom feeds from cybersecurity sources, matches them against
    keywords and MITRE ATT&CK techniques, extracts CVE identifiers, enriches
    them with NVD, CISA KEV and EPSS data, and generates HTML and CSV reports.
    Deduplication, HTTP caching metadata and feed health history are
    persisted in a state file.
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
    Kept for backward compatibility; the script has no prompts.
.PARAMETER NoOpenReport
    Do not automatically open the HTML report after generation.
.EXAMPLE
    .\ThreatRaven.ps1
.EXAMPLE
    .\ThreatRaven.ps1 -ConfigPath "C:\Config\custom.json" -OutputDir "C:\Reports" -NoOpenReport
#>

[CmdletBinding()]
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

if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
    if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $PSScriptRoot = (Get-Location).Path
    }
}

if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath = Join-Path $PSScriptRoot "config.json" }
if ([string]::IsNullOrWhiteSpace($LogDir))     { $LogDir = Join-Path $PSScriptRoot "logs" }
if ([string]::IsNullOrWhiteSpace($OutputDir))  { $OutputDir = $PSScriptRoot }
if ([string]::IsNullOrWhiteSpace($StatePath))  { $StatePath = Join-Path $PSScriptRoot "ThreatRavenState.json" }

# ============================================================
# CONSTANTS
# ============================================================
$script:SCRIPT_VERSION = '5.0'
$script:DEFAULT_MITRE_INITIAL_SHOW = 5
$script:DEFAULT_KEYWORD_TOP_N = 10
$script:LogLevel = 'Info'
$script:LogLevelRank = @{ Debug = 0; Info = 1; Warning = 2; Error = 3 }

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
[System.Net.ServicePointManager]::DefaultConnectionLimit = 64
[System.Net.ServicePointManager]::Expect100Continue = $false

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

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$script:LogFile = Join-Path $LogDir "ThreatFeed_$script:Timestamp.log"
$script:LogWriter = $null
try {
    $script:LogWriter = [System.IO.StreamWriter]::new($script:LogFile, $true, [System.Text.UTF8Encoding]::new($false))
    $script:LogWriter.AutoFlush = $true
}
catch {
    Write-Warning "Could not open log file ${script:LogFile}: $($_.Exception.Message)"
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a structured (JSON-lines) timestamped log entry. The file gets
        everything; the console is filtered by Settings.LogLevel.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Debug', 'Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $entry = [ordered]@{
        ts    = [DateTime]::UtcNow.ToString('o')
        level = $Level
        msg   = $Message
    }

    if ($null -ne $script:LogWriter) {
        try { $script:LogWriter.WriteLine(($entry | ConvertTo-Json -Compress)) }
        catch { Write-Warning "Failed to write to log file: $($_.Exception.Message)" }
    }

    if (-not $script:QuietMode) {
        $minRank = $script:LogLevelRank[$script:LogLevel]
        if ($null -eq $minRank) { $minRank = 1 }
        if ($script:LogLevelRank[$Level] -lt $minRank) { return }
        $color = switch ($Level) {
            'Info'    { 'Cyan' }
            'Warning' { 'Yellow' }
            'Error'   { 'Red' }
            'Debug'   { 'DarkGray' }
        }
        Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] [$Level] $Message" -ForegroundColor $color
    }
}

function Write-Console {
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
$script:StateLockStream = $null
$script:RunspacePool = $null
$script:RunspacePoolOpen = $false
$script:State = $null
$script:FeedHealth = $null
$script:StateRetentionDays = 90
$script:StateMaxEntries = 20000

try {
    Write-Log "=== ThreatRaven v$script:SCRIPT_VERSION ===" -Level Info
    Write-Log "by Diyar Abbas | github.com/diyarit/ThreatRaven" -Level Info
    Write-Log "Script started at: $script:Timestamp (PowerShell $($PSVersionTable.PSVersion))" -Level Info

    # ---------------------------------------------------------
    # Configuration
    # ---------------------------------------------------------
    $config = Initialize-Configuration -Path $ConfigPath
    $Settings = $config.Settings

    $script:VulnDays                  = [int]$Settings.VulnDays
    $script:ThrottleLimit             = [int]$Settings.ThrottleLimit
    $script:FeedTimeoutSeconds        = [int]$Settings.FeedTimeoutSeconds
    $script:MaxRetries                = [int]$Settings.MaxRetries
    $script:RetryBaseDelaySeconds     = [int]$Settings.RetryBaseDelaySeconds
    $script:MaxResponseBytes          = [long]$Settings.MaxResponseBytes
    $script:LogLevel                  = [string]$Settings.LogLevel
    $script:ValidateCertificates      = [bool]$Settings.ValidateCertificates
    $script:ExportHealthEnabled       = $ExportHealthReport -or [bool]$Settings.ExportHealthReport
    $script:NvdEnabled                = [bool]$Settings.NvdEnabled
    $script:NvdApiKey                 = [string]$Settings.NvdApiKey
    $script:NvdMaxResults             = [int]$Settings.NvdMaxResults
    $script:NvdCacheHours             = [int]$Settings.NvdCacheHours
    $script:NvdKeywordFilter          = [bool]$Settings.NvdKeywordFilter
    $script:KevEnabled                = [bool]$Settings.KevEnabled
    $script:EpssEnabled               = [bool]$Settings.EpssEnabled
    $script:EnrichmentCacheHours      = [int]$Settings.EnrichmentCacheHours
    $script:MitreMinKeywordHits       = [int]$Settings.MitreMinKeywordHits
    $script:MinHostRequestIntervalMs  = [int]$Settings.MinHostRequestIntervalMs
    $script:GlobalTimeoutSeconds      = [int]$Settings.GlobalTimeoutSeconds
    $script:StateRetentionDays        = [int]$Settings.StateRetentionDays
    $script:StateMaxEntries           = [int]$Settings.StateMaxEntries
    $script:ReportHistoryDays         = [int]$Settings.ReportHistoryDays
    $script:LogRetentionDays          = [int]$Settings.LogRetentionDays
    $script:EnableConditionalRequests = [bool]$Settings.EnableConditionalRequests
    $script:WebhookEnabled            = [bool]$Settings.WebhookEnabled
    $script:WebhookUrl                = [string]$Settings.WebhookUrl

    $script:HostIntervalOverrides = @{}
    if ($Settings.PSObject.Properties['HostRequestIntervalMsOverrides'] -and $null -ne $Settings.HostRequestIntervalMsOverrides) {
        $ovSetting = $Settings.HostRequestIntervalMsOverrides
        if ($ovSetting -is [hashtable]) {
            foreach ($k in $ovSetting.Keys) { $script:HostIntervalOverrides[[string]$k] = [int]$ovSetting[$k] }
        }
        else {
            foreach ($p in $ovSetting.PSObject.Properties) { $script:HostIntervalOverrides[[string]$p.Name] = [int]$p.Value }
        }
    }

    $FeedDefs = @(Get-FeedDefinitions -Config $config)
    Write-Log "Configuration loaded: $($FeedDefs.Count) feeds, $(@($config.Keywords).Count) keywords, $(@($config.MitreKeywords.PSObject.Properties.Name).Count) MITRE techniques" -Level Info

    # Rotate old logs
    $logCutoff = (Get-Date).AddDays(-$script:LogRetentionDays)
    Get-ChildItem -LiteralPath $LogDir -Filter 'ThreatFeed_*.log' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $logCutoff } |
        Remove-Item -Force -ErrorAction SilentlyContinue

    # ---------------------------------------------------------
    # Certificate validation (process-global; compiled callback so it is
    # safe on runspace-less threadpool threads)
    # ---------------------------------------------------------
    if ($script:ValidateCertificates) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }
    else {
        Write-Log "TLS certificate validation is DISABLED (ValidateCertificates=false). Feeds are exposed to man-in-the-middle tampering." -Level Warning
        if (-not ('ThreatRaven.CertPolicy' -as [type])) {
            Add-Type -TypeDefinition @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace ThreatRaven
{
    public static class CertPolicy
    {
        public static bool AcceptAll(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        public static void Enable()
        {
            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(AcceptAll);
        }
    }
}
"@
        }
        [ThreatRaven.CertPolicy]::Enable()
    }

    # ---------------------------------------------------------
    # Persistent state (exclusive lock for the whole run)
    # ---------------------------------------------------------
    $stateDir = Split-Path -Parent $StatePath
    if (-not [string]::IsNullOrWhiteSpace($stateDir) -and -not (Test-Path -LiteralPath $stateDir)) {
        New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
    }
    $stateLockPath = "$StatePath.lock"
    try {
        # DeleteOnClose: the lock disappears even if the process is killed.
        $script:StateLockStream = [System.IO.FileStream]::new(
            $stateLockPath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::DeleteOnClose)
    }
    catch {
        throw "Could not acquire the state lock ($stateLockPath) - another ThreatRaven instance is likely running. ($($_.Exception.Message))"
    }

    $script:State = Initialize-ThreatRavenState -Path $StatePath
    Write-Log "State loaded: $($script:State.Items.Count) known links" -Level Debug

    $ExistingLinks = [System.Collections.Concurrent.ConcurrentDictionary[string,bool]]::new([StringComparer]::OrdinalIgnoreCase)
    $script:HostGate = [System.Collections.Concurrent.ConcurrentDictionary[string,long]]::new([StringComparer]::OrdinalIgnoreCase)
    $StateSeenBefore = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    if (-not $SkipDeduplication) {
        foreach ($key in $script:State.Items.Keys) {
            $null = $StateSeenBefore.Add($key)
            $null = $ExistingLinks.TryAdd($key, $true)
        }
    }

    if ($PreviousCsvPath -and (Test-Path -LiteralPath $PreviousCsvPath)) {
        Write-Log "Seeding deduplication from previous CSV: $PreviousCsvPath" -Level Info
        try {
            $previousRows = @(Import-Csv -Path $PreviousCsvPath -Encoding UTF8)
            $nowStr = [DateTime]::UtcNow.ToString('o')
            foreach ($row in $previousRows) {
                if (-not $row.PSObject.Properties['Link'] -or [string]::IsNullOrWhiteSpace($row.Link)) { continue }
                $norm = ConvertTo-NormalizedUrl -Url $row.Link
                if ([string]::IsNullOrWhiteSpace($norm)) { continue }
                $null = $ExistingLinks.TryAdd($norm, $true)
                $null = $StateSeenBefore.Add($norm)
                if (-not $script:State.Items.ContainsKey($norm)) {
                    $get = { param($n) if ($row.PSObject.Properties[$n]) { [string]$row.$n } else { '' } }
                    $script:State.Items[$norm] = [PSCustomObject]@{
                        Normalized      = $norm
                        Date            = (ConvertTo-DateTime -InputObject (& $get 'Date') -Fallback ([DateTime]::UtcNow)).ToString('o')
                        Source          = & $get 'Source'
                        SourceName      = & $get 'SourceName'
                        Category        = & $get 'Category'
                        Title           = & $get 'Title'
                        Keywords        = & $get 'Keywords'
                        MitreTechniques = & $get 'MitreTechniques'
                        Cves            = & $get 'Cves'
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

    # ---------------------------------------------------------
    # Compile regexes ONCE. Regex objects are immutable and thread-safe, and
    # runspace parameters are passed by reference in-process, so every
    # worker shares these instances.
    # ---------------------------------------------------------
    $rxOpts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
              [System.Text.RegularExpressions.RegexOptions]::Compiled -bor
              [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    $rxTimeout = [TimeSpan]::FromSeconds(2)

    $KeywordNames = [string[]]@($config.Keywords | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { [string]$_ })
    $KeywordRegexes = [System.Text.RegularExpressions.Regex[]]@($KeywordNames | ForEach-Object {
        [regex]::new("\b" + [regex]::Escape($_) + "\b", $rxOpts, $rxTimeout)
    })

    # One alternation regex per technique; matched distinct terms are counted
    # against MitreMinKeywordHits.
    $MitreRegexes = @{}
    foreach ($tid in $config.MitreKeywords.PSObject.Properties.Name) {
        $tech = $config.MitreKeywords.$tid
        $terms = @($tech.Keywords | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { [regex]::Escape([string]$_) } | Sort-Object -Property Length -Descending)
        if ($terms.Count -eq 0) { continue }
        $MitreRegexes[$tid.ToUpperInvariant()] = [PSCustomObject]@{
            Id    = $tid.ToUpperInvariant()
            Name  = [string]$tech.Name
            Regex = [regex]::new("\b(?:" + ($terms -join '|') + ")\b", $rxOpts, $rxTimeout)
        }
    }
    Write-Log "Compiled $($KeywordRegexes.Count) keyword patterns and $($MitreRegexes.Count) MITRE technique patterns" -Level Debug

    # ---------------------------------------------------------
    # Paths and shared collections
    # ---------------------------------------------------------
    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        Write-Log "Created output directory: $OutputDir" -Level Info
    }

    $CsvPath = Join-Path $OutputDir "APT_Report_$script:Timestamp.csv"
    $HtmlPath = Join-Path $OutputDir "APT_Report_$script:Timestamp.html"
    $HealthReportPath = Join-Path $OutputDir "FeedHealth_$script:Timestamp.json"
    $ConfigSnapshotPath = Join-Path $OutputDir "RunConfig_$script:Timestamp.json"

    $Results = [System.Collections.Generic.List[PSObject]]::new()
    $script:FeedHealth = [System.Collections.Concurrent.ConcurrentDictionary[string,PSObject]]::new()
    $FeedDefByUrl = @{}
    foreach ($fd in $FeedDefs) { $FeedDefByUrl[$fd.Url] = $fd }

    Save-RunConfiguration -Config $config -Path $ConfigSnapshotPath -StatePath $StatePath

    Write-Console "`n=== ThreatRaven v$script:SCRIPT_VERSION ===" -ForegroundColor Cyan
    if (-not $SkipDeduplication) {
        Write-Console "Deduplicating against state file ($($script:State.Items.Count) known links)" -ForegroundColor Yellow
    }

    function Update-FeedHealth {
        [CmdletBinding()]
        param(
            [string]$FeedUrl,
            [bool]$Success,
            [int]$ItemsProcessed = 0,
            [int]$MatchesFound = 0,
            [string]$ErrorMessage = "",
            [double]$DurationMs = 0,
            [int]$StatusCode = 0
        )

        $def = $FeedDefByUrl[$FeedUrl]
        $hostName = try { ([System.Uri]$FeedUrl).Host } catch { $FeedUrl }
        $health = $null
        if (-not $script:FeedHealth.TryGetValue($FeedUrl, [ref]$health)) {
            $health = [PSCustomObject]@{
                FeedUrl        = $FeedUrl
                Name           = if ($def) { $def.Name } else { $hostName }
                Category       = if ($def) { $def.Category } else { 'General' }
                Host           = $hostName
                SuccessCount   = 0
                FailureCount   = 0
                TotalItems     = 0
                TotalMatches   = 0
                LastError      = ""
                LastStatusCode = 0
                LastChecked    = $null
                RecentRuns     = 0
                RecentFailures = 0
                ResponseTimes  = [System.Collections.Generic.List[double]]::new()
            }
            $null = $script:FeedHealth.TryAdd($FeedUrl, $health)
        }

        $health.LastChecked = Get-Date
        $health.LastStatusCode = $StatusCode
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

        $hist = Update-FeedRunHistory -State $script:State -FeedUrl $FeedUrl -Success $Success
        $health.RecentRuns = $hist.RecentRuns
        $health.RecentFailures = $hist.RecentFailures
    }

    # ---------------------------------------------------------
    # Worker scriptblock (runs in the runspace pool)
    # ---------------------------------------------------------
    $FeedScriptBlock = {
        param(
            [string]$Url,
            [string]$FeedName,
            [string[]]$KeywordNames,
            [System.Text.RegularExpressions.Regex[]]$KeywordRegexes,
            [hashtable]$MitreRegexes,
            [int]$MitreMinHits,
            $ExistingLinksRef,
            [int]$TimeoutSeconds,
            [int]$MaxRetryCount,
            [int]$RetryBaseSec,
            [long]$MaxBytes,
            [string[]]$UserAgentList,
            [string]$ModulePath,
            [hashtable]$FeedCache,
            [bool]$UseConditionalRequests,
            $HostGateRef,
            [string]$HostGateKey,
            [int]$HostIntervalMs,
            [bool]$SkipCertValidation
        )

        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'
        if (-not (Get-Command -Name Invoke-FeedFetchWithRetry -ErrorAction SilentlyContinue)) {
            Import-Module $ModulePath -ErrorAction Stop | Out-Null
        }

        $started = [Diagnostics.Stopwatch]::StartNew()
        $result = [PSCustomObject]@{
            Url             = $Url
            Results         = [System.Collections.Generic.List[PSObject]]::new()
            Error           = $null
            Warning         = $null
            Unchanged       = $false
            StatusCode      = 0
            Requests        = 0
            MatchCount      = 0
            DupCount        = 0
            NoLinkCount     = 0
            ItemsProcessed  = 0
            FetchDurationMs = 0
            Cache           = $FeedCache
        }

        $fetch = Invoke-FeedFetchWithRetry -Url $Url -UserAgents $UserAgentList -TimeoutSeconds $TimeoutSeconds `
            -MaxRetries $MaxRetryCount -RetryBaseSeconds $RetryBaseSec -FeedCache $FeedCache `
            -UseConditionalRequests $UseConditionalRequests -HostGate $HostGateRef -HostGateKey $HostGateKey `
            -HostIntervalMs $HostIntervalMs -MaxBytes $MaxBytes -SkipCertificateValidation $SkipCertValidation

        $result.FetchDurationMs = $started.Elapsed.TotalMilliseconds
        $result.StatusCode = $fetch.StatusCode
        $result.Requests = $fetch.Requests

        if (-not $fetch.Success) {
            $result.Error = $fetch.Error
            return $result
        }
        if ($fetch.Unchanged) {
            $result.Unchanged = $true
            $result.Warning = 'Unchanged (conditional request)'
            if ($null -ne $FeedCache) { $FeedCache['LastFetch'] = [DateTime]::UtcNow.ToString('o') }
            return $result
        }

        $parsed = ConvertFrom-FeedContent -Bytes $fetch.Bytes
        if ($parsed.Error) {
            $result.Error = $parsed.Error
            return $result
        }

        $items = @($parsed.Items)
        foreach ($item in $items) {
            $result.ItemsProcessed++

            # 1. Link + dedupe first: no regex work for items we already know.
            $itemLink = Get-ItemLink -Item $item -FeedUrl $Url
            if ([string]::IsNullOrWhiteSpace($itemLink)) { $result.NoLinkCount++; continue }
            if (-not (Test-UrlSafety -Url $itemLink)) { $result.NoLinkCount++; continue }
            $normLink = ConvertTo-NormalizedUrl -Url $itemLink
            if ([string]::IsNullOrWhiteSpace($normLink)) { $result.NoLinkCount++; continue }
            if ($ExistingLinksRef.ContainsKey($normLink)) { $result.DupCount++; continue }

            # 2. Text + keyword match
            $fullText = Get-AllTextContent -Item $item
            if ([string]::IsNullOrWhiteSpace($fullText)) { continue }

            $matchedKeywords = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            for ($ki = 0; $ki -lt $KeywordRegexes.Count; $ki++) {
                try {
                    if ($KeywordRegexes[$ki].IsMatch($fullText)) { $null = $matchedKeywords.Add($KeywordNames[$ki]) }
                }
                catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { }
            }
            if ($matchedKeywords.Count -eq 0) { continue }

            $result.MatchCount++

            # 3. MITRE: keyword-based (min distinct hits) + explicit technique IDs
            $detected = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
            foreach ($tid in $MitreRegexes.Keys) {
                $entry = $MitreRegexes[$tid]
                try {
                    $ms = $entry.Regex.Matches($fullText)
                    if ($ms.Count -eq 0) { continue }
                    if ($MitreMinHits -le 1) { $null = $detected.Add("$tid - $($entry.Name)"); continue }
                    $distinct = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    foreach ($m in $ms) { $null = $distinct.Add($m.Value) }
                    if ($distinct.Count -ge $MitreMinHits) { $null = $detected.Add("$tid - $($entry.Name)") }
                }
                catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { }
            }
            foreach ($explicitId in (Get-MitreIdsFromText -Text $fullText)) {
                if ($MitreRegexes.ContainsKey($explicitId)) {
                    $null = $detected.Add("$explicitId - $($MitreRegexes[$explicitId].Name)")
                }
                else {
                    $null = $detected.Add("$explicitId - Referenced technique")
                }
            }

            $cves = @(Get-CveIdsFromText -Text $fullText)

            $result.Results.Add([PSCustomObject]@{
                Date            = Get-FeedItemDate -Item $item
                Source          = $Url
                SourceName      = $FeedName
                Title           = Get-FeedItemTitle -Item $item
                Keywords        = ($matchedKeywords -join ', ')
                MitreTechniques = ($detected -join '; ')
                Cves            = ($cves -join ', ')
                Link            = $itemLink
                Normalized      = $normLink
            })
        }

        # Only now (parsed OK) is it safe to remember the validators.
        if ($UseConditionalRequests -and $null -ne $FeedCache -and $null -ne $fetch.Headers) {
            $etag = Get-WebResponseHeader -Response $fetch.Headers -Name 'ETag'
            $lastMod = Get-WebResponseHeader -Response $fetch.Headers -Name 'Last-Modified'
            if ($etag)    { $FeedCache['Etag'] = $etag } else { $FeedCache.Remove('Etag') }
            if ($lastMod) { $FeedCache['LastModified'] = $lastMod } else { $FeedCache.Remove('LastModified') }
            $FeedCache['LastFetch'] = [DateTime]::UtcNow.ToString('o')
        }

        if ($result.ItemsProcessed -eq 0) { $result.Warning = 'No items' }
        return $result
    }

    # ---------------------------------------------------------
    # Runspace pool: module imported once per runspace
    # ---------------------------------------------------------
    Write-Log "Starting feed scraping..." -Level Info
    Write-Log "Total Feeds: $($FeedDefs.Count) | Parallel workers: $script:ThrottleLimit | Timeout: ${script:FeedTimeoutSeconds}s | Response cap: $([math]::Round($script:MaxResponseBytes / 1MB, 1)) MB" -Level Info

    $script:StartTime = Get-Date

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    $iss.ImportPSModule([string[]]@($script:ModulePath))
    $script:RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $script:ThrottleLimit, $iss, $Host)
    $script:RunspacePool.Open()
    $script:RunspacePoolOpen = $true

    # Dispatch order: first occurrence of each host first, then second
    # occurrences, so repeat-host feeds (paced by the gate) never delay others.
    $hostOccurrence = @{}
    $feedBuckets = [System.Collections.Generic.SortedDictionary[int, System.Collections.Generic.List[PSObject]]]::new()
    foreach ($fd in $FeedDefs) {
        $h = try { ([System.Uri]$fd.Url).Host } catch { '' }
        $occ = 0
        if ($hostOccurrence.ContainsKey($h)) { $occ = $hostOccurrence[$h] }
        $hostOccurrence[$h] = $occ + 1
        if (-not $feedBuckets.ContainsKey($occ)) {
            $feedBuckets[$occ] = [System.Collections.Generic.List[PSObject]]::new()
        }
        $feedBuckets[$occ].Add($fd)
    }

    $RunspaceHandles = [System.Collections.Generic.List[PSObject]]::new()
    $CurrentFeed = 0
    foreach ($bucket in $feedBuckets.Values) {
        foreach ($fd in $bucket) {
            $url = $fd.Url
            $CurrentFeed++

            if (-not (Test-UrlSafety -Url $url -AllowedPatterns $config.AllowedUrlPatterns)) {
                Write-Log "Skipping invalid URL: $url" -Level Warning
                Update-FeedHealth -FeedUrl $url -Success $false -ErrorMessage 'Rejected by AllowedUrlPatterns'
                continue
            }

            $hostKey = ([System.Uri]$url).Host
            $gateKey = $hostKey
            $intervalMs = $script:MinHostRequestIntervalMs
            foreach ($ovHost in $script:HostIntervalOverrides.Keys) {
                if (($hostKey -eq $ovHost -or $hostKey.EndsWith('.' + $ovHost, [StringComparison]::OrdinalIgnoreCase)) -and
                    $script:HostIntervalOverrides[$ovHost] -gt $intervalMs) {
                    $intervalMs = $script:HostIntervalOverrides[$ovHost]
                    $gateKey = $ovHost
                }
            }

            $feedCacheEntry = @{}
            if ($script:State.FeedCache.ContainsKey($url)) {
                $cachedEntry = $script:State.FeedCache[$url]
                if ($cachedEntry -is [hashtable]) {
                    foreach ($k in $cachedEntry.Keys) { $feedCacheEntry[$k] = $cachedEntry[$k] }
                }
                else {
                    foreach ($cp in $cachedEntry.PSObject.Properties) { $feedCacheEntry[$cp.Name] = $cp.Value }
                }
            }

            $ps = [System.Management.Automation.PowerShell]::Create()
            $ps.RunspacePool = $script:RunspacePool

            $null = $ps.AddScript($FeedScriptBlock).AddParameters(@{
                Url                     = $url
                FeedName                = $fd.Name
                KeywordNames            = $KeywordNames
                KeywordRegexes          = $KeywordRegexes
                MitreRegexes            = $MitreRegexes
                MitreMinHits            = $script:MitreMinKeywordHits
                ExistingLinksRef        = $ExistingLinks
                TimeoutSeconds          = $script:FeedTimeoutSeconds
                MaxRetryCount           = $script:MaxRetries
                RetryBaseSec            = $script:RetryBaseDelaySeconds
                MaxBytes                = $script:MaxResponseBytes
                UserAgentList           = [string[]]@($config.UserAgents)
                ModulePath              = $script:ModulePath
                FeedCache               = $feedCacheEntry
                UseConditionalRequests  = $script:EnableConditionalRequests
                HostGateRef             = $script:HostGate
                HostGateKey             = $gateKey
                HostIntervalMs          = $intervalMs
                SkipCertValidation      = (-not $script:ValidateCertificates)
            })

            $handle = $ps.BeginInvoke()
            $RunspaceHandles.Add([PSCustomObject]@{
                PowerShell = $ps
                Handle     = $handle
                Url        = $url
                Name       = $fd.Name
                Index      = $CurrentFeed
                StartTime  = Get-Date
                Cache      = $feedCacheEntry
            })
        }
    }

    # ---------------------------------------------------------
    # Collect results as they complete (global deadline enforced)
    # ---------------------------------------------------------
    $NewLinksCount = 0
    $DuplicatesSkipped = 0
    $Completed = 0
    $DispatchedFeeds = $RunspaceHandles.Count
    $TotalRequests = 0

    $deadline = [DateTime]::UtcNow.AddSeconds($script:GlobalTimeoutSeconds)
    $pending = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($h in $RunspaceHandles) { $pending.Add($h) }

    function Complete-FeedJob {
        param($job)

        $output = $job.PowerShell.EndInvoke($job.Handle)
        foreach ($errRecord in $job.PowerShell.Streams.Error) {
            Write-Log "Worker error [$($job.Name)]: $errRecord" -Level Warning
        }
        $result = @($output)[0]

        if ($null -eq $result) {
            Write-Console " - No result returned" -ForegroundColor DarkYellow
            Update-FeedHealth -FeedUrl $job.Url -Success $false -ErrorMessage 'Feed returned no result'
            return
        }

        if ($result.Cache -is [hashtable] -and $result.Cache.Count -gt 0) {
            $script:State.FeedCache[$job.Url] = $result.Cache
        }

        $success = [string]::IsNullOrEmpty($result.Error)
        Update-FeedHealth -FeedUrl $job.Url -Success $success `
            -ItemsProcessed $result.ItemsProcessed -MatchesFound $result.MatchCount `
            -ErrorMessage ([string]$result.Error) -DurationMs ([double]$result.FetchDurationMs) -StatusCode ([int]$result.StatusCode)
        $script:TotalRequests += [int]$result.Requests
        $script:DuplicatesSkipped += $result.DupCount

        if ($result.Error) {
            Write-Console " - $($result.Error)" -ForegroundColor DarkYellow
        }
        elseif ($result.Unchanged) {
            Write-Console " - Unchanged (cached)" -ForegroundColor DarkGray
        }
        elseif ($result.MatchCount -gt 0) {
            $msg = " - Found $($result.MatchCount) new"
            if ($result.DupCount -gt 0) { $msg += " ($($result.DupCount) known)" }
            if ($result.NoLinkCount -gt 0) { $msg += " ($($result.NoLinkCount) without link)" }
            Write-Console $msg -ForegroundColor Green
        }
        elseif ($result.Warning) {
            Write-Console " - $($result.Warning)" -ForegroundColor DarkGray
        }
        elseif ($result.DupCount -gt 0) {
            Write-Console " - No new matches ($($result.DupCount) known)" -ForegroundColor DarkGray
        }
        else {
            Write-Console " - No matches" -ForegroundColor DarkGray
        }

        foreach ($item in $result.Results) {
            $norm = [string]$item.Normalized
            if ([string]::IsNullOrWhiteSpace($norm)) { continue }

            # Same article from two feeds in one run: first one wins.
            if (-not $ExistingLinks.TryAdd($norm, $true)) {
                $script:DuplicatesSkipped++
                continue
            }

            $isNew = -not $StateSeenBefore.Contains($norm)
            if ($isNew) { $script:NewLinksCount++ }

            $nowStr = [DateTime]::UtcNow.ToString('o')
            $itemDate = if ($item.Date -is [DateTime]) { $item.Date } else { ConvertTo-DateTime -InputObject ([string]$item.Date) -Fallback ([DateTime]::UtcNow) }
            if ($script:State.Items.ContainsKey($norm)) {
                $script:State.Items[$norm].LastSeen = $nowStr
            }
            else {
                $script:State.Items[$norm] = [PSCustomObject]@{
                    Normalized      = $norm
                    Date            = $itemDate.ToString('o')
                    Source          = $item.Source
                    SourceName      = $item.SourceName
                    Category        = $FeedDefByUrl[$job.Url].Category
                    Title           = $item.Title
                    Keywords        = $item.Keywords
                    MitreTechniques = $item.MitreTechniques
                    Cves            = $item.Cves
                    Link            = $item.Link
                    FirstSeen       = $nowStr
                    LastSeen        = $nowStr
                }
            }

            $Results.Add([PSCustomObject]@{
                Date            = $itemDate
                Source          = $item.Source
                SourceName      = $item.SourceName
                Category        = $FeedDefByUrl[$job.Url].Category
                Title           = $item.Title
                Keywords        = $item.Keywords
                MitreTechniques = $item.MitreTechniques
                Cves            = $item.Cves
                Link            = $item.Link
                Normalized      = $norm
                IsNew           = $isNew
            })
        }
    }

    Write-Console ""
    while ($pending.Count -gt 0) {
        if ([DateTime]::UtcNow -ge $deadline) {
            foreach ($job in $pending.ToArray()) {
                Write-Log "Global timeout waiting for feed: $($job.Url)" -Level Warning
                Update-FeedHealth -FeedUrl $job.Url -Success $false -ErrorMessage "Global timeout (${script:GlobalTimeoutSeconds}s)"
                try { $null = $job.PowerShell.BeginStop($null, $null) } catch { }
            }
            $pending.Clear()
            break
        }

        $found = $false
        foreach ($job in $pending.ToArray()) {
            if (-not $job.Handle.IsCompleted) { continue }
            $found = $true
            $null = $pending.Remove($job)
            $Completed++
            $pct = if ($DispatchedFeeds -gt 0) { [math]::Round(($Completed / $DispatchedFeeds) * 100) } else { 100 }
            Write-ProgressIfNotQuiet -Activity "Scanning feeds" -Status "Completed $Completed of $DispatchedFeeds ($pct%) - $($job.Name)" -PercentComplete $pct
            Write-Console "[$Completed/$DispatchedFeeds] $($job.Name)" -ForegroundColor Gray

            try {
                Complete-FeedJob -job $job
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
        if (-not $found) { Start-Sleep -Milliseconds 150 }
    }

    if ($script:RunspacePoolOpen) {
        try { $script:RunspacePool.Close(); $script:RunspacePool.Dispose() } catch { }
        $script:RunspacePoolOpen = $false
    }
    Write-ProgressIfNotQuiet -Activity "Scanning feeds" -Status "Complete" -PercentComplete 100
    if (-not $script:QuietMode) { Write-Progress -Activity "Scanning feeds" -Completed }

    $FetchDuration = ((Get-Date) - $script:StartTime).TotalSeconds

    # ---------------------------------------------------------
    # Feed health
    # ---------------------------------------------------------
    if ($script:ExportHealthEnabled) {
        Export-FeedHealthReport -FeedHealth $script:FeedHealth -Path $HealthReportPath
        Write-Log "Feed health report exported: $HealthReportPath" -Level Info
    }

    $healthReport = Get-FeedHealthReport -FeedHealth $script:FeedHealth
    Write-Log "=== Feed Health Summary ===" -Level Info
    Write-Log "Healthy: $($healthReport.Healthy) | Degraded: $($healthReport.Degraded) | Unhealthy: $($healthReport.Unhealthy) | HTTP requests: $TotalRequests | Fetch phase: $([math]::Round($FetchDuration, 1))s" -Level Info
    foreach ($unhealthyFeed in $healthReport.UnhealthyFeeds) {
        Write-Log "$($unhealthyFeed.Status): $($unhealthyFeed.Name) ($($unhealthyFeed.Feed)) - $($unhealthyFeed.LastError)" -Level Warning
    }

    # ---------------------------------------------------------
    # Merge with recent history, sort
    # ---------------------------------------------------------
    Write-Log "New matches found: $NewLinksCount | Duplicates skipped: $DuplicatesSkipped" -Level Info

    $runKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $Results) { $null = $runKeys.Add([string]$item.Normalized) }

    if (-not $SkipDeduplication -and $script:ReportHistoryDays -gt 0) {
        foreach ($h in @(Get-ThreatRavenHistoryItems -State $script:State -Days $script:ReportHistoryDays)) {
            $get = { param($n) if ($h.PSObject.Properties[$n] -and $null -ne $h.$n) { [string]$h.$n } else { '' } }
            $norm = & $get 'Normalized'
            if ([string]::IsNullOrWhiteSpace($norm)) { $norm = ConvertTo-NormalizedUrl -Url (& $get 'Link') }
            if ([string]::IsNullOrWhiteSpace($norm)) { continue }
            if (-not $runKeys.Add($norm)) { continue }

            $srcUrl = & $get 'Source'
            $srcName = & $get 'SourceName'
            if (-not $srcName) { $srcName = if ($FeedDefByUrl.ContainsKey($srcUrl)) { $FeedDefByUrl[$srcUrl].Name } else { try { ([System.Uri]$srcUrl).Host } catch { $srcUrl } } }
            $cat = & $get 'Category'
            if (-not $cat) { $cat = if ($FeedDefByUrl.ContainsKey($srcUrl)) { $FeedDefByUrl[$srcUrl].Category } else { 'General' } }

            $Results.Add([PSCustomObject]@{
                Date            = ConvertTo-DateTime -InputObject (& $get 'Date') -Fallback ([DateTime]::UtcNow)
                Source          = $srcUrl
                SourceName      = $srcName
                Category        = $cat
                Title           = & $get 'Title'
                Keywords        = & $get 'Keywords'
                MitreTechniques = & $get 'MitreTechniques'
                Cves            = & $get 'Cves'
                Link            = & $get 'Link'
                Normalized      = $norm
                IsNew           = $false
            })
        }
    }

    $AllResults = @($Results | Sort-Object -Property Date -Descending)

    # ---------------------------------------------------------
    # CSV
    # ---------------------------------------------------------
    $AllResults |
        Select-Object @{ Name = 'Date'; Expression = { $_.Date.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' } },
            SourceName, Category, Source, Title, Keywords, MitreTechniques, Cves, Link,
            @{ Name = 'IsNew'; Expression = { if ($_.IsNew) { 'true' } else { 'false' } } } |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV exported to: $CsvPath" -Level Info

    # ---------------------------------------------------------
    # Statistics
    # ---------------------------------------------------------
    $KeywordStats = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::OrdinalIgnoreCase)
    $MitreStats = [System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::OrdinalIgnoreCase)
    $ArticleCves = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($result in $AllResults) {
        if ($result.Keywords) {
            foreach ($kw in ($result.Keywords -split ',\s*')) {
                $kw = $kw.Trim()
                if ($kw -eq '') { continue }
                if ($KeywordStats.ContainsKey($kw)) { $KeywordStats[$kw]++ } else { $KeywordStats[$kw] = 1 }
            }
        }
        if ($result.MitreTechniques) {
            foreach ($tech in ($result.MitreTechniques -split ';\s*')) {
                $tech = $tech.Trim()
                if ($tech -eq '') { continue }
                if ($MitreStats.ContainsKey($tech)) { $MitreStats[$tech]++ } else { $MitreStats[$tech] = 1 }
            }
        }
        if ($result.Cves) {
            foreach ($c in ($result.Cves -split ',\s*')) { if ($c.Trim()) { $null = $ArticleCves.Add($c.Trim()) } }
        }
    }

    # ---------------------------------------------------------
    # NVD + KEV + EPSS enrichment
    # ---------------------------------------------------------
    $nvd = $null
    $vulnError = ''
    if ($script:NvdEnabled) {
        try {
            $nvd = Get-NvdCves -Days $script:VulnDays -ApiKey $script:NvdApiKey `
                -MaxResults $script:NvdMaxResults -Keywords @($config.Keywords) `
                -KeywordFilter $script:NvdKeywordFilter -State $script:State `
                -CacheHours $script:NvdCacheHours
            Write-Log "NVD: $(@($nvd.Cves).Count) CVEs for the last $script:VulnDays days$(if ($nvd.Truncated) { ' (truncated)' })" -Level Info
        }
        catch {
            $vulnError = $_.Exception.Message
            Write-Log "NVD fetch failed: $vulnError" -Level Warning
        }
    }
    else {
        Write-Log "NVD integration disabled (NvdEnabled=false)" -Level Debug
    }

    $kev = @{}
    if ($script:KevEnabled) {
        try {
            $kev = Get-CisaKev -State $script:State -CacheHours $script:EnrichmentCacheHours
            Write-Log "CISA KEV: $($kev.Count) exploited CVEs loaded" -Level Info
        }
        catch {
            Write-Log "KEV download failed: $($_.Exception.Message)" -Level Warning
        }
    }

    $epss = @{}
    if ($script:EpssEnabled) {
        try {
            $epssWanted = [System.Collections.Generic.List[string]]::new()
            foreach ($c in $ArticleCves) { $epssWanted.Add($c) }
            if ($null -ne $nvd) {
                foreach ($c in @($nvd.Cves)) { if (-not $ArticleCves.Contains([string]$c.id)) { $epssWanted.Add([string]$c.id) } }
            }
            $epss = Get-EpssScores -CveIds $epssWanted.ToArray() -State $script:State -CacheHours $script:EnrichmentCacheHours
            Write-Log "EPSS: scores for $($epss.Count) of $($epssWanted.Count) CVEs" -Level Info
        }
        catch {
            Write-Log "EPSS lookup failed: $($_.Exception.Message)" -Level Warning
        }
    }

    $TotalDuration = ((Get-Date) - $script:StartTime).TotalSeconds

    # ---------------------------------------------------------
    # Report data (serialized to JSON; the template parses it)
    # ---------------------------------------------------------
    $KevArticleCount = 0
    $reportItems = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $AllResults) {
        $local = $item.Date.ToLocalTime()
        $cveList = @()
        if ($item.Cves) { $cveList = @(($item.Cves -split ',\s*') | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() }) }
        $kevHit = $false
        foreach ($c in $cveList) { if ($kev.ContainsKey($c)) { $kevHit = $true; break } }
        if ($kevHit) { $KevArticleCount++ }
        $maxEpss = 0.0
        foreach ($c in $cveList) { if ($epss.ContainsKey($c) -and [double]$epss[$c].Epss -gt $maxEpss) { $maxEpss = [double]$epss[$c].Epss } }

        $reportItems.Add([ordered]@{
            ts     = [Math]::Floor(([DateTimeOffset]$item.Date).ToUnixTimeSeconds())
            dt     = $local.ToString('yyyy-MM-dd HH:mm')
            src    = [string]$item.SourceName
            srcUrl = [string]$item.Source
            cat    = [string]$item.Category
            ttl    = [string]$item.Title
            kw     = [string]$item.Keywords
            mitre  = [string]$item.MitreTechniques
            cves   = $cveList
            kev    = $kevHit
            epss   = [math]::Round($maxEpss, 3)
            lnk    = [string]$item.Link
            new    = [bool]$item.IsNew
        })
    }

    $reportHealth = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $script:FeedHealth.GetEnumerator()) {
        $v = $entry.Value
        $avg = 0
        if ($v.ResponseTimes.Count -gt 0) { $sum = 0.0; foreach ($t in $v.ResponseTimes) { $sum += $t }; $avg = [math]::Round($sum / $v.ResponseTimes.Count) }
        $reportHealth.Add([ordered]@{
            host    = [string]$v.Host
            name    = [string]$v.Name
            cat     = [string]$v.Category
            url     = [string]$entry.Key
            status  = Get-FeedStatusLabel -SuccessCount $v.SuccessCount -FailureCount $v.FailureCount -RecentRuns $v.RecentRuns -RecentFailures $v.RecentFailures
            ok      = [int]$v.SuccessCount
            fail    = [int]$v.FailureCount
            recentFail = [int]$v.RecentFailures
            recentRuns = [int]$v.RecentRuns
            items   = [int]$v.TotalItems
            matches = [int]$v.TotalMatches
            ms      = [int]$avg
            http    = [int]$v.LastStatusCode
            err     = [string]$v.LastError
            checked = if ($v.LastChecked) { $v.LastChecked.ToString('yyyy-MM-dd HH:mm') } else { '' }
        })
    }

    $reportVulns = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $nvd) {
        foreach ($cve in @($nvd.Cves)) {
            $id = [string]$cve.id
            $k = if ($kev.ContainsKey($id)) { $kev[$id] } else { $null }
            $e = if ($epss.ContainsKey($id)) { $epss[$id] } else { $null }
            $reportVulns.Add([ordered]@{
                id          = $id
                published   = [string]$cve.published
                severity    = [string]$cve.severity
                score       = [math]::Round([double]$cve.score, 1)
                cvss        = if ($cve.PSObject.Properties['cvss']) { [string]$cve.cvss } else { '' }
                description = [string]$cve.description
                kev         = ($null -ne $k)
                kevRansom   = if ($null -ne $k) { [bool]$k.Ransomware } else { $false }
                epss        = if ($null -ne $e) { [math]::Round([double]$e.Epss, 3) } else { $null }
                epssPct     = if ($null -ne $e) { [math]::Round([double]$e.Percentile * 100) } else { $null }
            })
        }
    }

    $kwStatsObj = [ordered]@{}
    foreach ($kv in ($KeywordStats.GetEnumerator() | Sort-Object -Property Value -Descending)) { $kwStatsObj[$kv.Key] = $kv.Value }
    $mitreStatsObj = [ordered]@{}
    foreach ($kv in ($MitreStats.GetEnumerator() | Sort-Object -Property Value -Descending)) { $mitreStatsObj[$kv.Key] = $kv.Value }

    $tzOffset = [TimeZoneInfo]::Local.GetUtcOffset([DateTime]::Now)
    $tzLabel = 'UTC' + $(if ($tzOffset -ge [TimeSpan]::Zero) { '+' } else { '-' }) + $tzOffset.ToString('hh\:mm')

    $reportData = [ordered]@{
        meta = [ordered]@{
            version         = $script:SCRIPT_VERSION
            generated       = [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm') + ' UTC'
            runDay          = (Get-Date).ToString('yyyy-MM-dd')
            tz              = $tzLabel
            vulnDays        = $script:VulnDays
            mitreInitialShow = $script:DEFAULT_MITRE_INITIAL_SHOW
            keywordTopN     = $script:DEFAULT_KEYWORD_TOP_N
            feedsCount      = $FeedDefs.Count
            timeSeconds     = [math]::Round($TotalDuration, 1)
            newCount        = $NewLinksCount
            totalCount      = $AllResults.Count
            kevArticles     = $KevArticleCount
            kevEnabled      = $script:KevEnabled
            epssEnabled     = $script:EpssEnabled
        }
        items        = $reportItems.ToArray()
        keywordStats = $kwStatsObj
        mitreStats   = $mitreStatsObj
        feedHealth   = $reportHealth.ToArray()
        vuln         = [ordered]@{
            error     = $vulnError
            truncated = if ($null -ne $nvd) { [bool]$nvd.Truncated } else { $false }
            enabled   = $script:NvdEnabled
            cves      = $reportVulns.ToArray()
        }
    }
    $reportJson = ConvertTo-EmbeddedJson -InputObject $reportData -Depth 8

    # ---------------------------------------------------------
    # HTML report
    # ---------------------------------------------------------
    Write-Console "`nGenerating HTML report..." -ForegroundColor Cyan

    $templatePath = Join-Path $PSScriptRoot "assets\report-template.html"
    if (-not (Test-Path -LiteralPath $templatePath)) {
        throw "Report template not found at: $templatePath"
    }
    $template = Get-Content -LiteralPath $templatePath -Raw -Encoding UTF8

    $chartLibInlined = $false
    $chartLibPath = Join-Path $PSScriptRoot "lib\chart.min.js"
    $chartScriptTag = "<script src='lib/chart.min.js' nonce='{{CSP_NONCE}}'></script>"
    if ((Test-Path -LiteralPath $chartLibPath) -and $template.Contains($chartScriptTag)) {
        $chartLibJs = Get-Content -LiteralPath $chartLibPath -Raw -Encoding UTF8
        if ($chartLibJs -notmatch '</script') {
            $template = $template.Replace($chartScriptTag, "<script nonce='{{CSP_NONCE}}'>`n$chartLibJs`n</script>")
            $chartLibInlined = $true
        }
    }

    $logoInlined = $false
    $logoPath = Join-Path $PSScriptRoot "assets\logo.png"
    if ((Test-Path -LiteralPath $logoPath) -and $template.Contains('src="assets/logo.png"')) {
        $logoB64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($logoPath))
        $template = $template.Replace('src="assets/logo.png"', "src=`"data:image/png;base64,$logoB64`"")
        $logoInlined = $true
    }

    $nonceBytes = New-Object byte[] 24
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($nonceBytes) } finally { $rng.Dispose() }
    $cspNonce = [Convert]::ToBase64String($nonceBytes)

    $HtmlContent = $template.Replace('{{CSP_NONCE}}', $cspNonce)
    $HtmlContent = $HtmlContent.Replace('{{REPORT_JSON}}', $reportJson)
    $HtmlContent = $HtmlContent.Replace('{{TOTAL_COUNT}}', [string]$AllResults.Count)
    $HtmlContent = $HtmlContent.Replace('{{NEW_COUNT}}', [string]$NewLinksCount)
    $HtmlContent = $HtmlContent.Replace('{{KEV_COUNT}}', [string]$KevArticleCount)
    $HtmlContent = $HtmlContent.Replace('{{MITRE_STAT_COUNT}}', [string]$MitreStats.Count)
    $HtmlContent = $HtmlContent.Replace('{{FEEDS_COUNT}}', [string]$FeedDefs.Count)
    $HtmlContent = $HtmlContent.Replace('{{TIME_SECONDS}}', [string][math]::Round($TotalDuration, 1))
    $HtmlContent = $HtmlContent.Replace('{{VULN_DAYS}}', [string]$script:VulnDays)
    $HtmlContent = $HtmlContent.Replace('{{SCRIPT_VERSION}}', $script:SCRIPT_VERSION)
    $HtmlContent = $HtmlContent.Replace('{{GENERATED}}', [string]$reportData.meta.generated)
    $HtmlContent = $HtmlContent.Replace('{{TZ}}', $tzLabel)

    [System.IO.File]::WriteAllText($HtmlPath, $HtmlContent, [System.Text.UTF8Encoding]::new($false))

    if (-not $chartLibInlined) {
        $libDest = Join-Path $OutputDir "lib"
        if ((Test-Path -LiteralPath $chartLibPath) -and $OutputDir -ne $PSScriptRoot) {
            if (-not (Test-Path -LiteralPath $libDest)) { New-Item -ItemType Directory -Path $libDest -Force | Out-Null }
            Copy-Item $chartLibPath $libDest -Force
        }
    }
    if (-not $logoInlined) {
        $logoDestDir = Join-Path $OutputDir "assets"
        if ((Test-Path -LiteralPath $logoPath) -and $OutputDir -ne $PSScriptRoot) {
            if (-not (Test-Path -LiteralPath $logoDestDir)) { New-Item -ItemType Directory -Path $logoDestDir -Force | Out-Null }
            Copy-Item $logoPath $logoDestDir -Force
        }
    }

    # ---------------------------------------------------------
    # Persist state, notify, summary
    # ---------------------------------------------------------
    try {
        $script:State.HealthHistory += [PSCustomObject]@{
            Timestamp     = [DateTime]::UtcNow.ToString('o')
            Healthy       = $healthReport.Healthy
            Degraded      = $healthReport.Degraded
            Unhealthy     = $healthReport.Unhealthy
            TotalSuccess  = $healthReport.TotalSuccess
            TotalFailures = $healthReport.TotalFailures
            NewItems      = $NewLinksCount
            DurationSeconds = [math]::Round($TotalDuration, 1)
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
            -TotalCount $AllResults.Count -FeedCount $FeedDefs.Count -UnhealthyCount $healthReport.Unhealthy `
            -KevArticleCount $KevArticleCount -DurationSeconds $TotalDuration -ReportPath $HtmlPath
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
    Write-Console "  Total in report:    $($AllResults.Count)" -ForegroundColor Cyan
    Write-Console "  KEV-linked items:   $KevArticleCount" -ForegroundColor Red
    Write-Console "  MITRE Techniques:   $($MitreStats.Count)" -ForegroundColor Magenta
    Write-Console "  Feeds unhealthy:    $($healthReport.Unhealthy) (degraded: $($healthReport.Degraded))" -ForegroundColor Yellow
    Write-Console "  Processing Time:    $([math]::Round($TotalDuration, 2))s ($TotalRequests HTTP requests)" -ForegroundColor Cyan
    if (-not $NoOpenReport) {
        Write-Console "`nOpening HTML report..." -ForegroundColor Yellow
        Start-Process $HtmlPath
    }
    else {
        Write-Console "`nHTML report ready: $HtmlPath" -ForegroundColor Yellow
    }
}
catch {
    Write-Log "Critical error: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error

    if ($script:RunspacePoolOpen -and $null -ne $script:RunspacePool) {
        try { $script:RunspacePool.Close(); $script:RunspacePool.Dispose() } catch { }
        $script:RunspacePoolOpen = $false
    }

    if ($script:State) {
        try {
            Save-ThreatRavenState -State $script:State -Path $StatePath `
                -RetentionDays $script:StateRetentionDays -MaxEntries $script:StateMaxEntries
        }
        catch { }
    }
    throw
}
finally {
    if ($null -ne $script:StateLockStream) {
        try { $script:StateLockStream.Dispose() } catch { }
        $script:StateLockStream = $null
    }
    if ($null -ne $script:LogWriter) {
        try { $script:LogWriter.Dispose() } catch { }
        $script:LogWriter = $null
    }
}
