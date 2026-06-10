# ============================================================
# ThreatRaven.ps1 — APT Intelligence Feed Monitor
# Version: 3.0
# Features: Parallel fetching, retry logic, external config,
#           health tracking, structured logging, security hardening,
#           XSS protection, CSP headers, certificate validation,
#           non-interactive mode, local Chart.js dependency
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
.PARAMETER ConfigPath
    Path to the JSON configuration file. Defaults to config.json in script directory.
.PARAMETER PreviousCsvPath
    Path to a previous CSV report for deduplication.
.PARAMETER SkipDeduplication
    Skip loading previous CSV for deduplication.
.PARAMETER LogDir
    Directory for log files. Defaults to 'logs' in script directory.
.PARAMETER OutputDir
    Directory for output files. Defaults to script directory.
.PARAMETER ExportHealthReport
    Export feed health data to JSON file.
.PARAMETER QuietMode
    Suppress console output (logs still written).
.PARAMETER NonInteractive
    Skip all interactive prompts. When set, deduplication is skipped unless -PreviousCsvPath is provided.
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

[CmdletBinding()]
param(
    [string]$ConfigPath = "",
    [string]$PreviousCsvPath,
    [switch]$SkipDeduplication,
    [string]$LogDir = "",
    [string]$OutputDir = "",
    [switch]$ExportHealthReport,
    [switch]$QuietMode,
    [switch]$NonInteractive,
    [switch]$NoOpenReport
)

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

# ============================================================
# CONSTANTS
# ============================================================
$script:SCRIPT_VERSION = '3.0'
$script:SECONDS_PER_DAY = 86400
$script:DEFAULT_MITRE_INITIAL_SHOW = 5
$script:DEFAULT_KEYWORD_TOP_N = 10
$script:MAX_RUNSPACE_TIMEOUT_MS = 300000  # 5 minutes per feed
$script:DEFAULT_CONFIG_VALUES = @{
    VulnDays              = 7
    ThrottleLimit         = 10
    FeedTimeoutSeconds    = 25
    MaxRetries            = 3
    RetryBaseDelaySeconds = 2
    LogLevel              = 'Info'
    ValidateCertificates  = $true
}

# ============================================================
# MODULE IMPORT
# ============================================================
$modulePath = Join-Path $PSScriptRoot "FeedHelpers.psm1"
if (-not (Test-Path $modulePath)) {
    Write-Error "Helper module not found at: $modulePath"
    exit 1
}
Import-Module $modulePath -Force

# ============================================================
# MAIN SCRIPT
# ============================================================
$script:Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($script:ScriptDir)) {
    $script:ScriptDir = (Get-Location).Path
}

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$script:LogFile = Join-Path $LogDir "ThreatFeed_$script:Timestamp.log"

function Write-Log {
    <#
    .SYNOPSIS
        Writes a timestamped log entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [ValidateSet('Debug', 'Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $logTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$logTimestamp] [$Level] $Message"
    
    if (-not $QuietMode) {
        switch ($Level) {
            'Debug'   { 
                if ($script:LogLevel -eq 'Debug') { 
                    Write-Verbose $logEntry -Verbose 
                } 
            }
            'Info'    { Write-Host $logEntry -ForegroundColor Cyan }
            'Warning' { Write-Host $logEntry -ForegroundColor Yellow }
            'Error'   { Write-Host $logEntry -ForegroundColor Red }
        }
    }
    
    try {
        $logEntry | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
    }
    catch {
        Write-Warning "Failed to write to log file: $($_.Exception.Message)"
    }
}

# ============================================================
# MAIN SCRIPT
# ============================================================
try {
    Write-Log "=== ThreatRaven v$script:SCRIPT_VERSION ===" -Level Info
    Write-Log "by Diyar Abbas | diyar.jaafar@gmail.com | github.com/diyarit" -Level Info
    Write-Log "Script started at: $script:Timestamp" -Level Info
    
    # Load configuration
    $config = Initialize-Configuration -Path $ConfigPath
    
    # Extract settings with defaults
    $Settings = $config.Settings
    $script:VulnDays = if ($Settings.VulnDays) { $Settings.VulnDays } else { $script:DEFAULT_CONFIG_VALUES.VulnDays }
    $script:ThrottleLimit = if ($Settings.ThrottleLimit) { $Settings.ThrottleLimit } else { $script:DEFAULT_CONFIG_VALUES.ThrottleLimit }
    $script:FeedTimeoutSeconds = if ($Settings.FeedTimeoutSeconds) { $Settings.FeedTimeoutSeconds } else { $script:DEFAULT_CONFIG_VALUES.FeedTimeoutSeconds }
    $script:MaxRetries = if ($Settings.MaxRetries) { $Settings.MaxRetries } else { $script:DEFAULT_CONFIG_VALUES.MaxRetries }
    $script:RetryBaseDelaySeconds = if ($Settings.RetryBaseDelaySeconds) { $Settings.RetryBaseDelaySeconds } else { $script:DEFAULT_CONFIG_VALUES.RetryBaseDelaySeconds }
    $script:LogLevel = if ($Settings.LogLevel) { $Settings.LogLevel } else { $script:DEFAULT_CONFIG_VALUES.LogLevel }
    $script:ValidateCertificates = if ($null -ne $Settings.ValidateCertificates) { $Settings.ValidateCertificates } else { $script:DEFAULT_CONFIG_VALUES.ValidateCertificates }
    
    Write-Log "Configuration loaded: $($config.Feeds.Count) feeds, $($config.Keywords.Count) keywords" -Level Info
    
    # Pre-compile regex patterns
    Write-Log "Pre-compiling regex patterns..." -Level Debug
    
    Add-Type -AssemblyName System.Text.RegularExpressions
    
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
    $ExistingLinks = [System.Collections.Concurrent.ConcurrentDictionary[string,bool]]::new()
    $script:FeedHealth = [System.Collections.Concurrent.ConcurrentDictionary[string,PSObject]]::new()
    
    # Save run configuration for audit
    Save-RunConfiguration -Config $config -Path $ConfigSnapshotPath
    
    # User input for deduplication
    Write-Host "`n=== ThreatRaven v$script:SCRIPT_VERSION ===" -ForegroundColor Cyan
    Write-Host "by Diyar Abbas | diyar.jaafar@gmail.com | github.com/diyarit" -ForegroundColor DarkGray
    Write-Host "This script will check for duplicate links from a previous report." -ForegroundColor Yellow
    
    $script:TrackNewLinks = $false
    $script:PreviousData = $null
    
    if ($SkipDeduplication) {
        Write-Log "Skipping deduplication (command-line parameter)" -Level Info
    }
    elseif ($PreviousCsvPath) {
        Write-Log "Using previous CSV path from command line: $PreviousCsvPath" -Level Info
        $script:TrackNewLinks = $true
    }
    elseif ($NonInteractive) {
        Write-Log "Skipping deduplication (non-interactive mode, no previous CSV specified)" -Level Info
    }
    else {
        Write-Host "`nDo you want to load a previous CSV file to avoid duplicates? (Y/N)" -ForegroundColor Green
        $loadPrevious = Read-Host "Enter choice"
        
        if ($loadPrevious -eq 'Y' -or $loadPrevious -eq 'y') {
            $script:TrackNewLinks = $true
            Write-Host "`nPlease enter the full path to the previous CSV file:" -ForegroundColor Cyan
            $PreviousCsvPath = Read-Host "CSV Path"
        }
    }
    
    if ($PreviousCsvPath -and (Test-Path $PreviousCsvPath)) {
        Write-Log "Loading previous data from: $PreviousCsvPath" -Level Info
        try {
            $script:PreviousData = Import-Csv -Path $PreviousCsvPath -Encoding UTF8
            foreach ($item in $script:PreviousData) {
                if ($item.Link -and $item.Link -ne '') {
                    $ExistingLinks.TryAdd($item.Link, $true) | Out-Null
                }
            }
            Write-Log "Loaded $($ExistingLinks.Count) existing links for deduplication" -Level Info
        }
        catch {
            Write-Log "Error reading previous CSV: $($_.Exception.Message)" -Level Error
            Write-Log "Continuing without deduplication..." -Level Warning
            $script:PreviousData = $null
        }
    }
    
    # Feed health tracking function
    function Update-FeedHealth {
        [CmdletBinding()]
        param(
            [string]$FeedUrl,
            [bool]$Success,
            [int]$ItemsProcessed = 0,
            [int]$MatchesFound = 0,
            [string]$ErrorMessage = ""
        )
        
        $hostName = ([System.Uri]$FeedUrl).Host
        
        $health = $script:FeedHealth.GetOrAdd($hostName, {
            [PSCustomObject]@{
                SuccessCount  = 0
                FailureCount  = 0
                TotalItems    = 0
                TotalMatches  = 0
                LastError     = ""
                LastChecked   = $null
                ResponseTimes = [System.Collections.Generic.List[double]]::new()
            }
        })
        
        $health.LastChecked = Get-Date
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
    
    # Parallel feed fetching
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
    
    $FeedScriptBlock = {
        param(
            [string]$Url,
            [string[]]$KeywordList,
            [hashtable]$RawMitre,
            $ExistingLinksRef,
            [bool]$TrackNew,
            [int]$TimeoutSeconds,
            [int]$MaxRetryCount,
            [int]$RetryBaseSec,
            [bool]$ValidateCert,
            [string[]]$UserAgentList
        )
        
        # Compile regex locally (cannot serialize across runspaces)
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
        
        # Inlined helper functions (cannot reference module from runspace)
        function Get-AllTextContent {
            param($Item)
            $textParts = [System.Collections.Generic.List[string]]::new()
            $fieldsToCheck = @('title','description','summary','content','encoded',
                'contentEncoded','content:encoded','#text','subtitle','rights','category')
            foreach ($field in $fieldsToCheck) {
                try {
                    if ($Item.PSObject.Properties[$field]) {
                        $value = $Item.$field
                        if ($value -is [string] -and $value.Trim() -ne '') { $textParts.Add($value) }
                        elseif ($value -is [System.Xml.XmlElement])        { $textParts.Add($value.InnerText) }
                        elseif ($value -is [array]) {
                            foreach ($v in $value) {
                                if ($v -is [string])   { $textParts.Add($v) }
                                elseif ($v.InnerText)  { $textParts.Add($v.InnerText) }
                            }
                        }
                    }
                } catch { }
            }
            try { if ($Item.'content:encoded') { $textParts.Add($Item.'content:encoded') } } catch { }
            if ($textParts.Count -eq 0) { return [string]::Empty }
            $combined = ($textParts -join ' ') -replace '<[^>]+>',' ' -replace '&nbsp;',' ' `
                -replace '&amp;','&' -replace '&lt;','<' -replace '&gt;','>' `
                -replace '&quot;','"' -replace '&#39;',"'"
            return $combined.Trim()
        }
        
        function Get-ItemLink {
            param($Item, $FeedUrl)
            $extractedLink = $null
            
            $getText = {
                param($Prop)
                if ($Prop -is [string]) { return $Prop }
                elseif ($Prop.'#text')  { return $Prop.'#text' }
                elseif ($Prop.href)     { return $Prop.href }
                elseif ($Prop.InnerText) { return $Prop.InnerText }
                return $null
            }
            
            if ($FeedUrl -match '0patch\.com') {
                if ($Item.link -and $Item.link -is [string] -and
                    $Item.link -match '^https?://blog\.0patch\.com/\d{4}/\d{2}/' -and
                    $Item.link -notmatch '/feeds/|/comments/') { return $Item.link.Trim() }
                if ($Item.guid) {
                    $gt = & $getText $Item.guid
                    if ($gt -match '^https?://blog\.0patch\.com/\d{4}/\d{2}/[^/]+\.html') { return $gt.Trim() }
                }
                $cs = ''
                if ($Item.content)     { $cs += & $getText $Item.content }
                if ($Item.description) { $cs += ' ' + (& $getText $Item.description) }
                if ($cs -match 'href="(https?://blog\.0patch\.com/\d{4}/\d{2}/[^"]+\.html)"') { return $matches[1].Trim() }
            }
            
            if ($FeedUrl -match 'any\.run') {
                if ($Item.link) { $extractedLink = & $getText $Item.link }
                if (-not $extractedLink -and $Item.guid) { $extractedLink = & $getText $Item.guid }
                if (-not $extractedLink -and $Item.id) { $extractedLink = $Item.id }
                if ($extractedLink) {
                    if     ($extractedLink -match '^/')                  { $extractedLink = "https://any.run$extractedLink" }
                    elseif ($extractedLink -match '^cybersecurity-blog') { $extractedLink = "https://any.run/$extractedLink" }
                    elseif ($extractedLink -match '^\?p=')               { $extractedLink = "https://any.run/cybersecurity-blog/$extractedLink" }
                    if ($extractedLink -match '^https?://any\.run/' -and $extractedLink -notmatch '\.xml$|/feed/?$') { return $extractedLink.Trim() }
                }
                $cs = ''
                if ($Item.description) { $cs += & $getText $Item.description }
                if ($Item.content)     { $cs += ' ' + (& $getText $Item.content) }
                if ($cs -match 'href="(https?://any\.run/[^"]+)"') { return $matches[1].Trim() }
            }
            
            if ($FeedUrl -match 'reddit\.com') {
                $rpl = $null
                if ($Item.link -and $Item.link -match 'reddit\.com/r/[^/]+/comments/') { $rpl = $Item.link }
                elseif ($Item.id -and $Item.id -match 'reddit\.com/r/[^/]+/comments/')  { $rpl = $Item.id }
                elseif ($Item.guid) {
                    $gv = & $getText $Item.guid
                    if ($gv -match 'reddit\.com/r/[^/]+/comments/') { $rpl = $gv }
                }
                if (-not $rpl) {
                    $cs = ''
                    if ($Item.content)     { $cs += & $getText $Item.content }
                    if ($Item.description) { $cs += ' ' + (& $getText $Item.description) }
                    if ($cs -match 'href="(https?://[^"]*reddit\.com/r/[^/]+/comments/[^"]*)"') { $rpl = $matches[1].Trim() }
                    elseif ($cs -match '(https?://[^\s<>"]*reddit\.com/r/[^/]+/comments/[^\s<>"]*)')  { $rpl = $matches[1].Trim() }
                }
                if ($rpl) { return $rpl.Trim() }
                return $null
            }
            
            $linkSources = @(
                { $Item.link }, { $Item.guid }, { $Item.id }, { $Item.url },
                { $Item.'feedburner:origLink' }, { $Item.origLink }
            )
            foreach ($src in $linkSources) {
                try {
                    $value = & $src
                    if ($value) {
                        $candidate = $null
                        if     ($value -is [string])  { $candidate = $value }
                        elseif ($value.href)          { $candidate = $value.href }
                        elseif ($value.'#text')       { $candidate = $value.'#text' }
                        elseif ($value.InnerText)     { $candidate = $value.InnerText }
                        elseif ($value -is [array]) {
                            foreach ($li in $value) {
                                $c = if ($li -is [string]) { $li } elseif ($li.href) { $li.href } else { $null }
                                if ($c -and $c -match '^https?://' -and $c -notmatch '\.xml$|/feed/?$|/rss/?$|/feeds/|/comments/') { $candidate = $c; break }
                            }
                        }
                        if ($candidate -and $candidate -match '^https?://' -and
                            $candidate -notmatch '\.xml$|/feed/?$|/rss/?$|/feeds/|/comments/') {
                            $extractedLink = $candidate; break
                        }
                    }
                } catch { }
            }
            
            if ((-not $extractedLink -or $extractedLink -eq $FeedUrl) -and $FeedUrl -match 'cisa\.gov') {
                if ($Item.id -or $Item.guid) {
                    $aid = if ($Item.id) { $Item.id } else { $Item.guid }
                    if ($aid -match '(AA|ICSA?|ICS-?ALERT|CSAF)-\d{2}-\d{3,6}') {
                        $extractedLink = "https://www.cisa.gov/news-events/cybersecurity-advisories/$aid"
                    }
                }
            }
            if ((-not $extractedLink -or $extractedLink -eq $FeedUrl) -and $FeedUrl -match 'talosintelligence|feedburner/Talos') {
                if ($Item.description -match 'href="(https?://[^"]+)"') { $extractedLink = $matches[1] }
            }
            if (-not $extractedLink -or
                $extractedLink -match '\.xml$|/feed/?$|/rss/?$|/feeds/.*comments|/comments/' -or
                $extractedLink -eq $FeedUrl) { $extractedLink = $FeedUrl }
            return $extractedLink.Trim()
        }
        
        # Fetch feed with retry and certificate validation
        $localResults = [System.Collections.Generic.List[PSObject]]::new()
        $webRequest = $null
        $fetchSuccess = $false
        $feedHost = ([System.Uri]$Url).Scheme + "://" + ([System.Uri]$Url).Host
        
        # Determine certificate validation option
        if ($ValidateCert) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
        } else {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }
        
        $attempt = 0
        $fetchStartTime = Get-Date
        
        while ($attempt -lt $MaxRetryCount -and -not $fetchSuccess) {
            $attempt++
            foreach ($agent in $UserAgentList) {
                try {
                    $webRequest = Invoke-WebRequest -Uri $Url -TimeoutSec $TimeoutSeconds -UseBasicParsing -Headers @{
                        "User-Agent"      = $agent
                        "Accept"          = "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"
                        "Accept-Language" = "en-US,en;q=0.9"
                        "Cache-Control"   = "no-cache"
                        "Referer"         = $feedHost
                    }
                    $fetchSuccess = $true
                    break
                }
                catch {
                    $errMsg = $_.Exception.Message
                    if ($errMsg -match '404|401|410|Not Found|Unauthorized|Gone') {
                        break
                    }
                    continue
                }
            }
            
            if (-not $fetchSuccess -and $attempt -lt $MaxRetryCount) {
                $delay = $RetryBaseSec * [Math]::Pow(2, $attempt - 1)
                $jitter = Get-Random -Minimum 0 -Maximum ([Math]::Max(1, [int]($delay / 2)))
                $totalDelay = $delay + $jitter
                Start-Sleep -Seconds $totalDelay
            }
        }
        
        $fetchDuration = ((Get-Date) - $fetchStartTime).TotalMilliseconds
        
        if (-not $fetchSuccess -or $null -eq $webRequest) {
            return [PSCustomObject]@{
                Url=$Url; Results=$localResults; Error='Fetch failed'; 
                MatchCount=0; DupCount=0; ItemsProcessed=0; FetchDurationMs=$fetchDuration
            }
        }
        
        # Parse XML with error handling
        try {
            $xmlDoc = New-Object System.Xml.XmlDocument
            $xmlDoc.LoadXml($webRequest.Content) | Out-Null
            $content = $xmlDoc
        }
        catch {
            # Retry: strip BOM and non-printable chars, then parse
            try {
                $cleaned = $webRequest.Content -replace '^\xEF\xBB\xBF', '' -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
                $xmlDoc = New-Object System.Xml.XmlDocument
                $xmlDoc.LoadXml($cleaned) | Out-Null
                $content = $xmlDoc
            }
            catch {
                return [PSCustomObject]@{
                    Url=$Url; Results=$localResults; Error="XML parse error: $($_.Exception.Message)"; 
                    MatchCount=0; DupCount=0; ItemsProcessed=0; FetchDurationMs=$fetchDuration
                }
            }
        }
        
        $items = @()
        if     ($content.rss.channel.item) { $items = $content.rss.channel.item }
        elseif ($content.feed.entry)       { $items = $content.feed.entry }
        elseif ($content.rdf.item)         { $items = $content.rdf.item }
        
        if ($items.Count -eq 0) {
            return [PSCustomObject]@{
                Url=$Url; Results=$localResults; Error='No items'; 
                MatchCount=0; DupCount=0; ItemsProcessed=0; FetchDurationMs=$fetchDuration
            }
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
            
            $itemTitle = 'Untitled'
            if ($item.title) {
                if     ($item.title -is [string]) { $itemTitle = $item.title.ToString().Trim() }
                elseif ($item.title.'#text')      { $itemTitle = $item.title.'#text'.ToString().Trim() }
                else                              { $itemTitle = $item.title.InnerText.Trim() }
            }
            
            $itemLink = Get-ItemLink -Item $item -FeedUrl $Url
            if ([string]::IsNullOrWhiteSpace($itemLink)) { continue }
            
            if ($ExistingLinksRef.ContainsKey($itemLink)) { $dupCount++; continue }
            
            $matchCount++
            
            $itemDate = Get-Date
            if ($item.pubDate) {
                $parsed = [DateTime]::MinValue
                if ([DateTime]::TryParse($item.pubDate, [ref]$parsed)) { $itemDate = $parsed }
            }
            elseif ($item.published) {
                $parsed = [DateTime]::MinValue
                if ([DateTime]::TryParse($item.published, [ref]$parsed)) { $itemDate = $parsed }
            }
            
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
                IsNew           = $TrackNew
            })
        }
        
        return [PSCustomObject]@{
            Url           = $Url
            Results       = $localResults
            Error         = $null
            MatchCount    = $matchCount
            DupCount      = $dupCount
            ItemsProcessed = $itemsProcessed
            FetchDurationMs = $fetchDuration
        }
    }
    
    # Dispatch runspaces
    $RunspaceHandles = [System.Collections.Generic.List[PSObject]]::new()
    $TotalFeeds = $config.Feeds.Count
    $CurrentFeed = 0
    
    foreach ($url in $config.Feeds) {
        $CurrentFeed++
        
        if (-not (Test-UrlSafety -Url $url -AllowedPatterns $config.AllowedUrlPatterns)) {
            Write-Log "Skipping invalid URL: $url" -Level Warning
            continue
        }
        
        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.RunspacePool = $RunspacePool
        
        $null = $ps.AddScript($FeedScriptBlock).AddParameters(@{
            Url              = $url
            KeywordList      = $config.Keywords
            RawMitre         = $RawMitreKeywords
            ExistingLinksRef = $ExistingLinks
            TrackNew         = $script:TrackNewLinks
            TimeoutSeconds   = $script:FeedTimeoutSeconds
            MaxRetryCount    = $script:MaxRetries
            RetryBaseSec     = $script:RetryBaseDelaySeconds
            ValidateCert     = $script:ValidateCertificates
            UserAgentList    = $config.UserAgents
        })
        
        $handle = $ps.BeginInvoke()
        $RunspaceHandles.Add([PSCustomObject]@{
            PowerShell = $ps
            Handle     = $handle
            Url        = $url
            Index      = $CurrentFeed
            StartTime  = Get-Date
        })
    }
    
    # Collect results with timeout
    $NewLinksCount = 0
    $DuplicatesSkipped = 0
    $Completed = 0
    $TotalFetchTimeMs = 0
    
    Write-Host ""
    foreach ($job in $RunspaceHandles) {
        $Completed++
        
        # Wait with timeout
        $waitResult = $job.Handle.AsyncWaitHandle.WaitOne($script:MAX_RUNSPACE_TIMEOUT_MS)
        
        if (-not $waitResult) {
            Write-Log "Timeout waiting for feed: $($job.Url)" -Level Warning
            Update-FeedHealth -FeedUrl $job.Url -Success $false -ErrorMessage "Timeout"
            $job.PowerShell.Stop()
            $job.PowerShell.Dispose()
            continue
        }
        
        $pct = [math]::Round(($Completed / $TotalFeeds) * 100)
        Write-Progress -Activity "Scanning RSS Feeds" -Status "Completed $Completed of $TotalFeeds ($pct%)" -PercentComplete $pct
        
        $feedName = ([System.Uri]$job.Url).Host
        Write-Host "[$Completed/$TotalFeeds] $feedName" -ForegroundColor Gray -NoNewline
        
        try {
            $result = $job.PowerShell.EndInvoke($job.Handle)
            
            Update-FeedHealth -FeedUrl $job.Url -Success ([string]::IsNullOrEmpty($result.Error)) -ItemsProcessed $result.ItemsProcessed -MatchesFound $result.MatchCount -ErrorMessage $result.Error
            $TotalFetchTimeMs += $result.FetchDurationMs
            
            if ($result.Error) {
                Write-Host " - $($result.Error)" -ForegroundColor DarkYellow
            }
            elseif ($result.MatchCount -gt 0) {
                $msg = " - Found $($result.MatchCount) new"
                if ($result.DupCount -gt 0) { $msg += " ($($result.DupCount) duplicates skipped)" }
                Write-Host $msg -ForegroundColor Green
            }
            else {
                Write-Host " - No matches" -ForegroundColor DarkGray
            }
            
            foreach ($item in $result.Results) {
                if (-not $ExistingLinks.ContainsKey($item.Link)) {
                    $ExistingLinks.TryAdd($item.Link, $true) | Out-Null
                    $ResultsBag.Add($item)
                    $NewLinksCount++
                }
                else {
                    $DuplicatesSkipped++
                }
            }
        }
        catch {
            Write-Host " - Runner error: $($_.Exception.Message)" -ForegroundColor Red
            Update-FeedHealth -FeedUrl $job.Url -Success $false -ErrorMessage $_.Exception.Message
        }
        
        $job.PowerShell.Dispose()
    }
    
    $RunspacePool.Close()
    $RunspacePool.Dispose()
    Write-Progress -Activity "Scanning RSS Feeds" -Completed
    
    $TotalDuration = ((Get-Date) - $script:StartTime).TotalSeconds
    
    # Export health report if requested
    if ($ExportHealthReport) {
        Export-FeedHealthReport -FeedHealth $script:FeedHealth -Path $HealthReportPath
        Write-Log "Feed health report exported: $HealthReportPath" -Level Info
    }
    
    # Feed health summary
    $healthReport = Get-FeedHealthReport -FeedHealth $script:FeedHealth
    Write-Log "`n=== Feed Health Summary ===" -Level Info
    Write-Log "Healthy: $($healthReport.Healthy) | Degraded: $($healthReport.Degraded) | Unhealthy: $($healthReport.Unhealthy)" -Level Info
    
    foreach ($unhealthyFeed in $healthReport.UnhealthyFeeds) {
        Write-Log "$($unhealthyFeed.Status): $($unhealthyFeed.Host) - $($unhealthyFeed.LastError)" -Level Warning
    }
    
    # Merge and sort results
    Write-Log "`nProcessing results..." -Level Info
    Write-Log "New matches found: $NewLinksCount" -Level Info
    Write-Log "Duplicates skipped: $DuplicatesSkipped" -Level Info
    
    $AllResultsList = [System.Collections.Generic.List[PSObject]]::new()
    $seenLinks = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    
    foreach ($item in $ResultsBag) {
        if ($seenLinks.Add($item.Link)) {
            $AllResultsList.Add($item)
        }
    }
    
    if ($script:PreviousData) {
        foreach ($prevItem in $script:PreviousData) {
            $AllResultsList.Add([PSCustomObject]@{
                Date            = $prevItem.Date
                Source          = $prevItem.Source
                Title           = $prevItem.Title
                Keywords        = $prevItem.Keywords
                MitreTechniques = if ($prevItem.PSObject.Properties['MitreTechniques']) { $prevItem.MitreTechniques } else { "" }
                Link            = $prevItem.Link
                IsNew           = $false
            })
        }
    }
    
    $AllResultsForCSV = $AllResultsList | Sort-Object {
        if ($_.Date -is [DateTime]) {
            $_.Date
        }
        else {
            $parsed = [DateTime]::MinValue
            if ([DateTime]::TryParse($_.Date, [ref]$parsed)) { $parsed } else { [DateTime]::new(2000,1,1) }
        }
    } -Descending
    
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
    
    # Build JavaScript data with proper escaping
    $jsDataItems = [System.Text.StringBuilder]::new()
    $firstItem = $true
    
    foreach ($item in $AllResultsForCSV) {
        $itemDate = if ($item.Date -is [DateTime]) {
            $item.Date
        }
        else {
            $parsed = [DateTime]::MinValue
            if ([DateTime]::TryParse($item.Date, [ref]$parsed)) { $parsed } else { Get-Date }
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
    
    # Build keyword JSON
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
    
    # Build MITRE JSON
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
    
    # Build Feed Health JSON
    $healthParts = [System.Text.StringBuilder]::new()
    $healthParts.Append('[') | Out-Null
    $firstHealth = $true
    foreach ($entry in $script:FeedHealth.GetEnumerator()) {
        if (-not $firstHealth) { $healthParts.Append(',') | Out-Null }
        $hHost = ConvertTo-JavaScriptString -Text $entry.Key
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
    
    # HTML Report with CSP
    Write-Host "`nGenerating HTML report..." -ForegroundColor Cyan
    
    $HtmlContent = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width, initial-scale=1.0'>
<meta http-equiv='Content-Security-Policy' content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://services.nvd.nist.gov;">
<title>APT Intelligence Report - MITRE ATT&CK</title>
<script src='lib/chart.min.js'></script>
<style>
:root{--bg:#0c0e12;--txt:#b0b8c4;--dim:#5a6370;--border:#1e2329;--accent:#00b4d8;--accent-g:rgba(0,180,216,0.12);--red:#ef4444;--green:#22c55e;--yellow:#eab308;--orange:#f97316;--surface:#13161c;--card:#161a22;--card-border:#1c2128}
[data-theme='light']{--bg:#f0f2f5;--txt:#2d3748;--dim:#8896a6;--border:#d1d9e0;--accent:#0284c7;--accent-g:rgba(2,132,199,0.08);--red:#dc2626;--green:#16a34a;--yellow:#ca8a04;--orange:#ea580c;--surface:#e8ecf0;--card:#fff;--card-border:#dce1e8}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter','SF Pro Text','Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--txt);font-size:16px;line-height:1.55;-webkit-font-smoothing:antialiased}
::selection{background:var(--accent);color:#fff}
.wrap{max-width:1900px;margin:0 auto;padding:24px 40px}

.hdr{display:flex;align-items:center;gap:18px;padding:16px 20px;background:var(--card);border:1px solid var(--card-border);border-radius:10px;margin-bottom:16px;box-shadow:0 2px 8px rgba(0,0,0,0.25),0 1px 2px rgba(0,0,0,0.15)}
.hdr-icon{width:55px;height:55px;flex-shrink:0}
.hdr h1{font-size:20px;font-weight:700;color:var(--txt);letter-spacing:-0.2px}
.hdr h1 span{color:var(--accent);font-weight:800}
.hdr-sub{font-size:11px;color:var(--dim);margin-top:1px}
.hdr-ver{margin-left:auto;font-size:10px;color:var(--dim);background:var(--surface);border:1px solid var(--border);padding:4px 10px;border-radius:6px;font-weight:600;letter-spacing:0.5px}

.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:16px}
.stat{padding:14px 16px;background:var(--card);border:1px solid var(--card-border);border-radius:8px;text-align:center;box-shadow:0 1px 4px rgba(0,0,0,0.2)}
.stat:hover{border-color:var(--accent)}
.stat-n{font-size:30px;font-weight:800;color:#e2e8f0;line-height:1.1}
.stat-n.red{color:var(--red)}
.stat-n.grn{color:var(--green)}
.stat-n.ylw{color:var(--yellow)}
.stat-n.acc{color:var(--accent)}
.stat-l{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:1.2px;margin-top:4px;font-weight:600}

.fhp{border:1px solid var(--card-border);border-radius:10px;margin-bottom:16px;background:var(--card);box-shadow:0 1px 4px rgba(0,0,0,0.2);overflow:hidden}
.fhp-hdr{display:flex;justify-content:space-between;align-items:center;padding:10px 16px;cursor:pointer;user-select:none}
.fhp-hdr:hover{background:var(--surface)}
.fhp-hdr span:first-child{font-size:13px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--dim)}
.fhp-hdr .tog{font-size:10px;color:var(--accent);font-weight:700;background:var(--accent-g);padding:2px 8px;border-radius:4px}
.fhp-body{display:none;border-top:1px solid var(--border);padding:10px}
.fhp-body.open{display:block}
.fhp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:6px}
.fhp-item{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-radius:6px;font-size:13px;background:var(--surface);border:1px solid var(--border)}
.fhp-item:hover{border-color:var(--accent)}
.fhp-item .dot{width:6px;height:6px;border-radius:50%;margin-right:8px;flex-shrink:0}
.fhp-item .dot.g{background:var(--green);box-shadow:0 0 6px rgba(34,197,94,0.4)}
.fhp-item .dot.y{background:var(--yellow);box-shadow:0 0 6px rgba(234,179,8,0.4)}
.fhp-item .dot.r{background:var(--red);box-shadow:0 0 6px rgba(239,68,68,0.4)}
.fhp-item .host{font-weight:600;color:#e2e8f0;flex:1}
.fhp-item .meta{text-align:right;color:var(--dim);font-size:10px}
.fhp-item .meta b{color:var(--green);font-weight:700}
.fhp-item .meta .fl{color:var(--red)}
.fhp-item .err{font-size:9px;color:var(--dim);font-style:italic;margin-top:2px}

.ctrl{display:flex;gap:8px;align-items:center;margin-bottom:16px;flex-wrap:wrap}
.ctrl select,.ctrl input[type='text']{padding:9px 14px;border:1px solid var(--card-border);background:var(--card);color:var(--txt);font-family:inherit;font-size:14px;border-radius:6px}
.ctrl select:focus,.ctrl input[type='text']:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-g)}
.ctrl input[type='text']{width:280px}
.ctrl select{cursor:pointer;padding-right:28px;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%235a6370'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center;appearance:none}
.ctrl .spacer{flex:1}
.btn{padding:8px 16px;border:1px solid var(--card-border);background:var(--card);color:var(--txt);font-family:inherit;font-size:13px;font-weight:600;cursor:pointer;border-radius:6px;letter-spacing:0.3px}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn-r{border-color:rgba(239,68,68,0.3);color:var(--red)}
.btn-r:hover{background:var(--red);color:#fff;border-color:var(--red)}
.btn-o{border-color:rgba(249,115,22,0.3);color:var(--orange)}
.btn-o:hover{background:var(--orange);color:#fff;border-color:var(--orange)}

.tgl{display:flex;align-items:center;gap:6px}
.tgl-l{font-size:11px;color:var(--dim)}
.swt{position:relative;width:36px;height:18px}
.swt input{opacity:0;width:0;height:0}
.swt .s{position:absolute;cursor:pointer;inset:0;background:var(--border);border-radius:18px;transition:.25s;box-shadow:inset 0 1px 3px rgba(0,0,0,0.3)}
.swt .s:before{content:'';position:absolute;height:12px;width:12px;left:3px;bottom:3px;background:var(--dim);border-radius:50%;transition:.25s;box-shadow:0 1px 3px rgba(0,0,0,0.3)}
.swt input:checked+.s{background:var(--accent);box-shadow:inset 0 1px 3px rgba(0,0,0,0.2),0 0 8px rgba(0,180,216,0.3)}
.swt input:checked+.s:before{transform:translateX(18px);background:#fff}

.charts{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px}
.chart-box{padding:16px;background:var(--card);border:1px solid var(--card-border);border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,0.2)}
.chart-box h3{font-size:12px;text-transform:uppercase;letter-spacing:1.2px;color:var(--dim);margin-bottom:14px;font-weight:700}
.chart-inner{display:flex;align-items:center;gap:20px}
.chart-canvas{flex:0 0 150px;height:150px}
.chart-legend{flex:1}
.leg{display:flex;align-items:center;gap:8px;padding:5px 8px;border-radius:4px;font-size:14px}
.leg:hover{background:var(--accent-g)}
.leg-c{width:12px;height:4px;border-radius:2px;flex-shrink:0}
.leg-t{flex:1;color:var(--txt)}
.leg-n{color:var(--accent);font-weight:700;font-size:10px;background:var(--accent-g);padding:1px 6px;border-radius:3px}
.src-grid{display:grid;grid-template-columns:1fr;gap:4px}
.src-row{display:flex;align-items:center;gap:10px;font-size:14px;padding:4px 0}
.src-name{width:160px;color:var(--txt);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:500}
.src-bar-bg{flex:1;height:4px;background:var(--border);border-radius:2px;overflow:hidden}
.src-bar{height:100%;border-radius:2px;background:linear-gradient(90deg,var(--accent),#0077b6);transition:width .4s ease}
.src-cnt{width:24px;text-align:right;color:var(--accent);font-weight:700;font-size:10px}

.tbl-wrap{border:1px solid var(--card-border);border-radius:10px;overflow:hidden;background:var(--card);box-shadow:0 1px 4px rgba(0,0,0,0.2)}
table{width:100%;border-collapse:collapse}
th{background:var(--surface);color:var(--dim);font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:1px;padding:12px 14px;text-align:left;border-bottom:2px solid var(--border);cursor:pointer;white-space:nowrap;user-select:none}
th:hover{color:var(--accent)}
th .si{font-size:8px;margin-left:3px;opacity:.35}
th.asc .si,th.desc .si{opacity:1;color:var(--accent)}
td{padding:12px 14px;border-bottom:1px solid var(--border);font-size:15px;vertical-align:middle}
tr:hover{background:rgba(0,180,216,0.04)}
[data-theme='light'] tr:hover{background:rgba(2,132,199,0.04)}
td.kw{background:var(--accent-g);font-size:11px;font-weight:500;color:var(--accent)}
td.mt{background:rgba(249,115,22,0.06)}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline;color:#0ea5e9}
a.visited{color:#8b5cf6;opacity:.6}

.new{display:inline-block;background:var(--red);color:#fff;font-size:10px;font-weight:700;padding:2px 7px;border-radius:3px;letter-spacing:.5px;vertical-align:middle;margin-left:4px;animation:pulse 2s infinite;box-shadow:0 0 8px rgba(239,68,68,0.4)}
@keyframes pulse{0%,100%{box-shadow:0 0 4px rgba(239,68,68,0.3)}50%{box-shadow:0 0 12px rgba(239,68,68,0.5)}}
.nw-row{border-left:3px solid var(--red)}
.mit-b{display:inline-block;background:rgba(249,115,22,0.15);color:var(--orange);font-size:11px;font-weight:700;padding:3px 8px;border-radius:4px;margin:1px;white-space:nowrap;cursor:pointer;border:1px solid rgba(249,115,22,0.2)}
.mit-b:hover{background:var(--orange);color:#fff;border-color:var(--orange)}

.lnk-c{display:flex;flex-direction:column;gap:5px}
.lnk-a{font-size:14px;font-weight:600}
.ai-b{display:flex;gap:4px}
.ai-b button{display:inline-flex;align-items:center;gap:3px;padding:4px 10px;border:none;color:#fff;font-family:inherit;font-size:11px;font-weight:700;cursor:pointer;border-radius:4px;letter-spacing:.3px}
.ai-b button:hover{transform:translateY(-1px);box-shadow:0 2px 8px rgba(0,0,0,0.3)}
.ai-b .gpt{background:#10a37f}
.ai-b .cld{background:#d97757}
.ai-b .gem{background:#4285f4}
.ai-b svg{width:10px;height:10px;fill:currentColor}

.modal{display:none;position:fixed;inset:0;z-index:2000;background:rgba(0,0,0,0.8);backdrop-filter:blur(4px);overflow-y:auto}
.modal-c{background:var(--card);margin:4vh auto;width:94%;max-width:1100px;border:1px solid var(--card-border);border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,0.5);animation:modIn .2s ease-out}
@keyframes modIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
.modal-h{display:flex;justify-content:space-between;align-items:center;padding:14px 20px;border-bottom:1px solid var(--border);border-radius:12px 12px 0 0}
.modal-h h2{font-size:13px;font-weight:700;letter-spacing:0.5px}
.modal-h .x{background:var(--surface);border:1px solid var(--border);color:var(--dim);width:28px;height:28px;cursor:pointer;font-size:16px;display:grid;place-items:center;border-radius:6px}
.modal-h .x:hover{border-color:var(--red);color:var(--red)}
.modal-h.mo h2{color:var(--orange)}
.modal-h.mr h2{color:var(--red)}
.modal-b{padding:20px}

.mc-chart{height:250px;border:1px solid var(--card-border);border-radius:8px;padding:14px;margin-bottom:16px;background:var(--surface);box-shadow:inset 0 1px 4px rgba(0,0,0,0.15)}
.mc-ctrl{margin-bottom:14px}
.mc-ctrl input{width:100%;padding:9px 12px;border:1px solid var(--card-border);background:var(--card);color:var(--txt);font-family:inherit;font-size:12px;border-radius:6px}
.mc-ctrl input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-g)}
.mc-card{border:1px solid var(--card-border);border-left:3px solid var(--orange);padding:14px;margin-bottom:8px;border-radius:6px;background:var(--card)}
.mc-card:hover{border-left-color:var(--accent);transform:translateX(3px)}
.mc-card-h{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px}
.mc-id{font-size:11px;font-weight:800;color:var(--orange);font-family:'SF Mono',Consolas,monospace}
.mc-name{font-size:13px;color:#e2e8f0;margin-top:2px;font-weight:500}
.mc-cnt{background:rgba(249,115,22,0.15);color:var(--orange);font-size:10px;font-weight:700;padding:3px 10px;border-radius:12px;white-space:nowrap;border:1px solid rgba(249,115,22,0.2)}
.mc-list{padding-left:16px;font-size:11px}
.mc-list div{padding:3px 0;color:var(--txt)}
.mc-list a{color:var(--accent)}
.mc-list .dt{color:var(--dim);font-size:10px}
.mc-more{display:block;width:100%;padding:7px;margin-top:8px;border:1px solid var(--card-border);background:var(--surface);color:var(--dim);font-family:inherit;font-size:10px;font-weight:600;cursor:pointer;text-align:center;letter-spacing:1px;text-transform:uppercase;border-radius:6px}
.mc-more:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-g)}

.vc-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}
.vc-stat{padding:16px;border-radius:8px;text-align:center;cursor:pointer;background:var(--card);border:1px solid var(--card-border)}
.vc-stat:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,0.25)}
.vc-stat.on{border-color:var(--cc)}
.vc-stat .n{font-size:26px;font-weight:800;line-height:1}
.vc-stat .l{font-size:9px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-top:4px;font-weight:600}
.vc-stat.sc .n{color:var(--red)}.vc-stat.sc{--cc:var(--red)}
.vc-stat.sh .n{color:var(--orange)}.vc-stat.sh{--cc:var(--orange)}
.vc-stat.sm .n{color:var(--yellow)}.vc-stat.sm{--cc:var(--yellow)}
.vc-stat.sl .n{color:var(--green)}.vc-stat.sl{--cc:var(--green)}
.vc-chart{height:230px;border:1px solid var(--card-border);border-radius:8px;padding:14px;margin-bottom:16px;background:var(--surface);box-shadow:inset 0 1px 4px rgba(0,0,0,0.15)}
.vc-ctrl{margin-bottom:14px}
.vc-ctrl input{width:100%;padding:9px 12px;border:1px solid var(--card-border);background:var(--card);color:var(--txt);font-family:inherit;font-size:12px;border-radius:6px}
.vc-ctrl input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-g)}
.vc-tbl{width:100%;border-collapse:collapse}
.vc-tbl th{background:var(--surface);padding:8px 10px;font-size:9px;text-align:left;border-bottom:2px solid var(--border)}
.vc-tbl td{padding:8px 10px;border-bottom:1px solid var(--border);font-size:11px}
.vc-tbl tr:hover{background:rgba(0,180,216,0.04)}
.sev{display:inline-block;padding:2px 8px;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;border-radius:4px}
.sev-c{background:rgba(239,68,68,0.12);color:var(--red);border:1px solid rgba(239,68,68,0.2)}
.sev-h{background:rgba(249,115,22,0.12);color:var(--orange);border:1px solid rgba(249,115,22,0.2)}
.sev-m{background:rgba(234,179,8,0.12);color:var(--yellow);border:1px solid rgba(234,179,8,0.2)}
.sev-l{background:rgba(34,197,94,0.12);color:var(--green);border:1px solid rgba(34,197,94,0.2)}
.sev-u{background:var(--surface);color:var(--dim);border:1px solid var(--border)}
.scr{font-weight:800;font-size:11px;font-family:'SF Mono',Consolas,monospace}
.scr-c{color:var(--red)}.scr-h{color:var(--orange)}.scr-m{color:var(--yellow)}.scr-l{color:var(--green)}

.ld{text-align:center;padding:40px;color:var(--dim);font-size:12px}
.spn{width:24px;height:24px;border:2.5px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;margin:0 auto 12px}
@keyframes spin{to{transform:rotate(360deg)}}
.ftr{border-top:1px solid var(--border);padding:16px 0;margin-top:20px;color:var(--dim);font-size:13px;text-align:center}
.ftr b{color:var(--accent);font-weight:700}
.ftr a{color:var(--dim)}
.ftr a:hover{color:var(--accent)}
.btt{position:fixed;bottom:24px;right:24px;width:32px;height:32px;border:1px solid var(--card-border);background:var(--card);color:var(--dim);font-size:14px;cursor:pointer;display:grid;place-items:center;border-radius:8px;opacity:0;transition:opacity .2s;z-index:500;box-shadow:0 2px 8px rgba(0,0,0,0.3)}
.btt.on{opacity:1}
.btt:hover{border-color:var(--accent);color:var(--accent)}

@media(max-width:1200px){.charts{grid-template-columns:1fr}.stats{grid-template-columns:repeat(3,1fr)}}
@media(max-width:768px){.stats{grid-template-columns:repeat(2,1fr)}.hdr{flex-wrap:wrap}.ctrl{gap:6px}}
@media print{.ctrl,.tgl,.btt,.btn{display:none!important}body{background:#fff;color:#000}.hdr,.stat,.chart-box,.tbl-wrap,.fhp{border-color:#ccc!important;box-shadow:none!important}.new{animation:none;box-shadow:none}}
</style>
</head>
<body>
<div class="wrap">

<div class="hdr">
<div class="hdr-icon"><img src="assets/logo.png" alt="ThreatRaven" width="55" height="55" style="border-radius:4px"></div>
<div>
<h1><span>THREAT</span>RAVEN</h1>

</div>

</div>

<div class="stats">
<div class="stat"><div class="stat-n acc" id="totalCount">$($AllResultsForCSV.Count)</div><div class="stat-l">Total</div></div>
<div class="stat"><div class="stat-n red" id="newCount">$NewLinksCount</div><div class="stat-l">New</div></div>
<div class="stat"><div class="stat-n grn" id="displayedCount">$($AllResultsForCSV.Count)</div><div class="stat-l">Displayed</div></div>
<div class="stat"><div class="stat-n ylw" id="mitreCount">$($MitreStats.Count)</div><div class="stat-l">MITRE</div></div>
<div class="stat"><div class="stat-n acc" id="feedsCount">$TotalFeeds</div><div class="stat-l">Feeds</div></div>
<div class="stat"><div class="stat-n grn" id="timeCount">$([math]::Round($TotalDuration, 1))s</div><div class="stat-l">Time</div></div>
</div>

<div class="fhp">
<div class="fhp-hdr" onclick="toggleFeedHealth()">
<span>&#x25CF; Feed Health</span>
<span class="tog" id="fhpTog">&#x25BC;</span>
</div>
<div class="fhp-body" id="fhpBody">
<div class="fhp-grid" id="feedHealthGrid"></div>
</div>
</div>

<div class="ctrl">
<select id="dateFilter" onchange="filterData()">
<option value="all">All dates</option>
<option value="1">Today</option>
<option value="7">7 days</option>
<option value="30">30 days</option>
<option value="90">90 days</option>
<option value="180">6 months</option>
<option value="365">1 year</option>
</select>
<select id="statusFilter" onchange="filterData()">
<option value="all">All status</option>
<option value="new">New only</option>
<option value="old">Seen</option>
</select>
<button class="btn btn-r" onclick="openVulnModal()">CVE Report</button>
<button class="btn btn-o" onclick="openMitreModal()">MITRE ATT&CK</button>
<input type='text' id='searchInput' placeholder='Search keywords, titles...' onkeyup='filterData()'>
<div class="spacer"></div>
<div class="tgl">
<span class="tgl-l">&#x2600;&#xFE0F;</span>
<label class="swt"><input type="checkbox" id="themeToggle" checked onchange="toggleTheme()"><span class="s"></span></label>
<span class="tgl-l">&#x1F319;</span>
</div>
</div>

<div class="charts">
<div class="chart-box">
<h3>Keyword Distribution</h3>
<div class="chart-inner">
<div class="chart-canvas"><canvas id="chart"></canvas></div>
<div class="chart-legend" id="legend"></div>
</div>
</div>
<div class="chart-box">
<h3>Top Sources</h3>
<div class="src-grid" id="sourceList"></div>
</div>
</div>

<div class="tbl-wrap">
<table>
<thead>
<tr>
<th onclick="sortTable(0)" data-col="0">Date <span class="si">&#x25B2;&#x25BC;</span></th>
<th onclick="sortTable(1)" data-col="1">Source <span class="si">&#x25B2;&#x25BC;</span></th>
<th onclick="sortTable(2)" data-col="2">Title <span class="si">&#x25B2;&#x25BC;</span></th>
<th onclick="sortTable(3)" data-col="3">Keywords <span class="si">&#x25B2;&#x25BC;</span></th>
<th onclick="sortTable(4)" data-col="4">MITRE <span class="si">&#x25B2;&#x25BC;</span></th>
<th>Link</th>
</tr>
</thead>
<tbody id="tableBody"></tbody>
</table>
</div>

<div class="ftr">
ThreatRaven v$script:SCRIPT_VERSION &middot; Built by <b>Diyar Abbas</b>
</div>
</div>

<div id="mitreModal" class="modal">
<div class="modal-c">
<div class="modal-h mo">
<h2>MITRE ATT&CK</h2>
<button class="x" onclick="closeMitreModal()">&#xD7;</button>
</div>
<div class="modal-b">
<div class="mc-chart"><canvas id="mitreChart"></canvas></div>
<div class="mc-ctrl"><input type="text" id="mitreSearch" placeholder="filter technique..." onkeyup="filterMitreTechniques()"></div>
<div id="mitreContent"></div>
</div>
</div>
</div>

<div id="vulnModal" class="modal">
<div class="modal-c">
<div class="modal-h mr">
<h2>CVE &mdash; Last $script:VulnDays Days</h2>
<button class="x" onclick="closeVulnModal()">&#xD7;</button>
</div>
<div class="modal-b">
<div id="vulnLoading" class="ld">
<div class="spn"></div>
Fetching from NVD...
</div>
<div id="vulnContent" style="display:none">
<div class="vc-stats">
<div class="vc-stat sc" onclick="filterBySeverity('CRITICAL')"><div class="n" id="criticalCount">0</div><div class="l">Critical</div></div>
<div class="vc-stat sh" onclick="filterBySeverity('HIGH')"><div class="n" id="highCount">0</div><div class="l">High</div></div>
<div class="vc-stat sm" onclick="filterBySeverity('MEDIUM')"><div class="n" id="mediumCount">0</div><div class="l">Medium</div></div>
<div class="vc-stat sl" onclick="filterBySeverity('LOW')"><div class="n" id="lowCount">0</div><div class="l">Low</div></div>
</div>
<div class="vc-chart"><canvas id="vulnChart"></canvas></div>
<div class="vc-ctrl"><input type="text" id="vulnSearch" placeholder="filter CVE..." onkeyup="filterVulnTable()"></div>
<div class="tbl-wrap">
<table class="vc-tbl">
<thead><tr><th>CVE</th><th>Published</th><th>Severity</th><th>CVSS</th><th>Description</th></tr></thead>
<tbody id="vulnTableBody"></tbody>
</table>
</div>
</div>
</div>
</div>
</div>

<script>
const allData=$jsArray;
const keywordData=$jsKeywordsObj;
const mitreData=$jsMitreStats;
const feedHealthData=$jsFeedHealth;
const MITRE_INITIAL_SHOW=$script:DEFAULT_MITRE_INITIAL_SHOW;
const KEYWORD_TOP_N=$script:DEFAULT_KEYWORD_TOP_N;
let chart=null;
let mitreChart=null;
let vulnChart=null;
let allVulnData=[];
let filteredVulnData=[];
let activeSeverityFilter='ALL';
const colors=['#FF6384','#36A2EB','#FFCE56','#4BC0C0','#9966FF','#FF9F40','#E7E9ED','#8BC34A','#FF5722','#795548'];
const VULN_DAYS=$script:VulnDays;

function escapeHtml(text){
const div=document.createElement('div');
div.appendChild(document.createTextNode(String(text)));
return div.innerHTML;
}

let currentSort={col:-1,asc:true};
let filteredData=[];

function sortTable(colIndex){
const headers=document.querySelectorAll('th');
headers.forEach(h=>{h.classList.remove('asc','desc')});
if(currentSort.col===colIndex){currentSort.asc=!currentSort.asc}else{currentSort.col=colIndex;currentSort.asc=true}
headers[colIndex].classList.add(currentSort.asc?'asc':'desc');
headers[colIndex].querySelector('.si').innerHTML=currentSort.asc?'&#x25B2;':'&#x25BC;';
filteredData.sort((a,b)=>{
let va,vb;
switch(colIndex){
case 0:va=a.ts;vb=b.ts;break;
case 1:va=a.src.toLowerCase();vb=b.src.toLowerCase();break;
case 2:va=a.ttl.toLowerCase();vb=b.ttl.toLowerCase();break;
case 3:va=a.kw.toLowerCase();vb=b.kw.toLowerCase();break;
case 4:va=a.mitre.toLowerCase();vb=b.mitre.toLowerCase();break;
default:va='';vb='';
}
if(va<vb)return currentSort.asc?-1:1;
if(va>vb)return currentSort.asc?1:-1;
return 0;
});
renderTable();
}

function renderTable(){
const tbody=document.getElementById('tableBody');
tbody.innerHTML='';
filteredData.forEach(item=>{
const row=tbody.insertRow();
if(item.new)row.className='nw-row';
const escapedLink=escapeHtml(item.lnk);
const escapedTitle=escapeHtml(item.ttl);
const linkBadge=item.new?'<a href="'+escapedLink+'" target="_blank" class="lnk-a">Read Article</a><span class="new">NEW</span>':'<a href="'+escapedLink+'" target="_blank" class="lnk-a">Read Article</a>';
const mitreBadges=item.mitre?item.mitre.split(';').map(m=>'<span class="mit-b" onclick="searchMitre(\''+escapeHtml(m.trim().split(' ')[0])+'\')">'+escapeHtml(m.trim())+'</span>').join(''):'';
row.innerHTML='<td>'+escapeHtml(item.dt)+'</td><td>'+escapeHtml(item.src)+'</td><td>'+escapeHtml(item.ttl)+(item.new?'<span class="new">NEW</span>':'')+'</td><td class="kw">'+escapeHtml(item.kw)+'</td><td class="mt">'+mitreBadges+'</td><td><div class="lnk-c">'+linkBadge+'<div class="ai-b"><button class="gpt" onclick="openChatGPT(\''+escapedLink+'\',\''+escapedTitle+'\')"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M22.3 8.7c.2-.5.3-1 .3-1.5 0-1.7-.9-3.3-2.4-4.2-.8-.5-1.7-.8-2.6-.8-1 0-1.9.3-2.7.9-.8.6-1.4 1.4-1.7 2.3-.7.1-1.3.4-1.9.8-.6.4-1 1-1.3 1.6-.5.9-.7 1.9-.5 2.9.1 1 .6 1.9 1.3 2.6-.2.5-.3 1-.3 1.6 0 1.7.9 3.3 2.4 4.2.8.5 1.7.8 2.6.8 1 0 1.9-.3 2.7-.9.8-.6 1.4-1.4 1.7-2.3.7-.1 1.3-.4 1.9-.8.6-.4 1-1 1.3-1.6.5-.9.7-1.9.5-2.9-.1-1-.6-1.9-1.3-2.6z"/></svg>GPT</button><button class="cld" onclick="openClaude(\''+escapedLink+'\',\''+escapedTitle+'\')"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M17.5 3L7 8.5v7L17.5 21l10.5-5.5v-7L17.5 3z"/></svg>CLD</button><button class="gem" onclick="openGemini(\''+escapedLink+'\',\''+escapedTitle+'\')"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 2L2 7v10l10 5 10-5V7L12 2z"/></svg>GEM</button></div></div></td>';
});
document.getElementById('displayedCount').textContent=filteredData.length;
}

function toggleFeedHealth(){
const body=document.getElementById('fhpBody');
const tog=document.getElementById('fhpTog');
if(body.classList.contains('open')){body.classList.remove('open');tog.innerHTML='&#x25BC;'}
else{body.classList.add('open');tog.innerHTML='&#x25B2;'}
}

function renderFeedHealth(){
const grid=document.getElementById('feedHealthGrid');
if(!grid||!feedHealthData||feedHealthData.length===0){return}
grid.innerHTML='';
const sorted=[...feedHealthData].sort((a,b)=>{
const order={unhealthy:0,degraded:1,healthy:2};
return(order[a.status]||2)-(order[b.status]||2);
});
sorted.forEach(f=>{
const item=document.createElement('div');
item.className='fhp-item';
const dotClass=f.status==='healthy'?'g':f.status==='degraded'?'y':'r';
const errHtml=f.err?'<div class="err">'+escapeHtml(f.err)+'</div>':'';
item.innerHTML='<div style="display:flex;align-items:center;min-width:0;flex:1"><div class="dot '+dotClass+'"></div><span class="host">'+escapeHtml(f.host)+'</span>'+errHtml+'</div><div class="meta"><b>'+f.ok+'</b>/<span class="fl">'+f.fail+'</span> &middot; '+f.items+'</div>';
grid.appendChild(item);
});
}

function updateSourceDistribution(){
const srcCount={};
allData.forEach(item=>{srcCount[item.src]=(srcCount[item.src]||0)+1});
const sorted=Object.entries(srcCount).sort((a,b)=>b[1]-a[1]).slice(0,10);
const maxCount=sorted.length>0?sorted[0][1]:1;
const srcList=document.getElementById('sourceList');
if(!srcList)return;
srcList.innerHTML='';
sorted.forEach(([src,cnt])=>{
const pct=Math.round((cnt/maxCount)*100);
const item=document.createElement('div');
item.className='src-row';
item.innerHTML='<span class="src-name">'+escapeHtml(src)+'</span><div class="src-bar-bg"><div class="src-bar" style="width:'+pct+'%"></div></div><span class="src-cnt">'+cnt+'</span>';
srcList.appendChild(item);
});
}

window.addEventListener('scroll',function(){
const btn=document.getElementById('backToTop');
if(window.scrollY>300)btn.classList.add('on');
else btn.classList.remove('on');
});

function toggleTheme(){
const dark=document.getElementById('themeToggle').checked;
document.documentElement.setAttribute('data-theme',dark?'dark':'light');
localStorage.setItem('theme',dark?'dark':'light');
}

function loadTheme(){
const savedTheme=localStorage.getItem('theme');
if(!savedTheme){
document.documentElement.setAttribute('data-theme','dark');
document.getElementById('themeToggle').checked=true;
localStorage.setItem('theme','dark');
}else if(savedTheme==='dark'){
document.documentElement.setAttribute('data-theme','dark');
document.getElementById('themeToggle').checked=true;
}
}

function getDaysAgo(days){
return Math.floor(Date.now()/1000)-(days*86400);
}

function filterData(){
const search=document.getElementById('searchInput').value.toUpperCase();
const dateVal=document.getElementById('dateFilter').value;
const statusVal=document.getElementById('statusFilter').value;
const cutoff=dateVal==='all'?0:getDaysAgo(parseInt(dateVal));

let displayed=0;
let kwCount={};
filteredData=[];

allData.forEach(item=>{
const matchSearch=!search||(item.ttl.toUpperCase().includes(search)||item.src.toUpperCase().includes(search)||item.kw.toUpperCase().includes(search)||item.mitre.toUpperCase().includes(search));
const matchDate=dateVal==='all'||item.ts>=cutoff;
const matchStatus=statusVal==='all'||(statusVal==='new'&&item.new)||(statusVal==='old'&&!item.new);

if(matchSearch&&matchDate&&matchStatus){
displayed++;
filteredData.push(item);
item.kw.split(',').forEach(k=>{
k=k.trim();
if(k)kwCount[k]=(kwCount[k]||0)+1;
});
}
});

if(currentSort.col>=0)sortTable(currentSort.col);
else renderTable();

document.getElementById('displayedCount').textContent=displayed;
updateChart(kwCount);
updateSourceDistribution();
}

function updateChart(kwCount){
const sortedKw=Object.entries(kwCount).sort((a,b)=>b[1]-a[1]).slice(0,KEYWORD_TOP_N);
const labels=sortedKw.map(x=>x[0]);
const data=sortedKw.map(x=>x[1]);
const bgColors=sortedKw.map((x,i)=>colors[i%colors.length]);

const legendDiv=document.getElementById('legend');
legendDiv.innerHTML='';
sortedKw.forEach((kw,i)=>{
const item=document.createElement('div');
item.className='legend-item';
item.innerHTML='<div class="legend-color" style="background:'+bgColors[i]+'"></div><span class="legend-text">'+escapeHtml(kw[0])+'</span><span class="legend-count">'+kw[1]+'</span>';
legendDiv.appendChild(item);
});

if(chart)chart.destroy();
const ctx=document.getElementById('chart').getContext('2d');
chart=new Chart(ctx,{
type:'doughnut',
data:{labels:labels,datasets:[{data:data,backgroundColor:bgColors,borderWidth:2,borderColor:getComputedStyle(document.documentElement).getPropertyValue('--card')}]},
options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}}}
});
}

function openMitreModal(){
document.getElementById('mitreModal').style.display='block';
renderMitreTechniques();
updateMitreChart();
}

function closeMitreModal(){
document.getElementById('mitreModal').style.display='none';
}

function renderMitreTechniques(){
const mitreContent=document.getElementById('mitreContent');
mitreContent.innerHTML='';

const mitreMap={};
allData.forEach(item=>{
if(item.mitre){
item.mitre.split(';').forEach(tech=>{
const techTrim=tech.trim();
if(techTrim){
if(!mitreMap[techTrim]){
mitreMap[techTrim]={count:0,articles:[]};
}
mitreMap[techTrim].count++;
mitreMap[techTrim].articles.push({title:item.ttl,link:item.lnk,date:item.dt});
}
});
}
});

const sortedTechs=Object.entries(mitreMap).sort((a,b)=>b[1].count-a[1].count);

sortedTechs.forEach(([tech,data],index)=>{
const parts=tech.split(' - ');
const techId=parts[0];
const techName=parts.slice(1).join(' - ');

const hasMore = data.articles.length > MITRE_INITIAL_SHOW;
const articlesToShow = hasMore ? data.articles.slice(0, MITRE_INITIAL_SHOW) : data.articles;
const remainingCount = data.articles.length - MITRE_INITIAL_SHOW;

const card=document.createElement('div');
card.className='mc-card';

let html = '';
html += '<div class="mc-card-h">';
html += '<div><div class="mc-id">'+escapeHtml(techId)+'</div><div class="mc-name">'+escapeHtml(techName)+'</div></div>';
html += '<div class="mc-cnt">'+data.count+'</div>';
html += '</div>';

html += '<div class="mc-list" id="mitre-list-'+index+'">';
articlesToShow.forEach(art=>{
html += '<div>\u2022 <a href="'+escapeHtml(art.link)+'" target="_blank">'+escapeHtml(art.title)+'</a> <span class="dt">('+escapeHtml(art.date)+')</span></div>';
});
html += '</div>';

if(hasMore){
html += '<button class="mc-more" onclick="toggleMitreArticles('+index+', '+data.articles.length+')" id="toggle-btn-'+index+'">';
html += '\u25BC '+remainingCount+' more';
html += '</button>';

html += '<div class="mc-list" id="mitre-list-extra-'+index+'" style="display:none">';
data.articles.slice(MITRE_INITIAL_SHOW).forEach(art=>{
html += '<div>\u2022 <a href="'+escapeHtml(art.link)+'" target="_blank">'+escapeHtml(art.title)+'</a> <span class="dt">('+escapeHtml(art.date)+')</span></div>';
});
html += '</div>';
}

card.innerHTML = html;
mitreContent.appendChild(card);
});
}

function toggleMitreArticles(index, totalCount){
const extraList = document.getElementById('mitre-list-extra-' + index);
const toggleBtn = document.getElementById('toggle-btn-' + index);

if(extraList.style.display === 'none'){
extraList.style.display = 'block';
toggleBtn.innerHTML = '\u25B2 less';
toggleBtn.classList.add('expanded');
} else {
extraList.style.display = 'none';
const remainingCount = totalCount - MITRE_INITIAL_SHOW;
toggleBtn.innerHTML = '\u25BC ' + remainingCount + ' more';
toggleBtn.classList.remove('expanded');
}
}

function updateMitreChart(){
const sortedMitre=Object.entries(mitreData).sort((a,b)=>b[1]-a[1]).slice(0,KEYWORD_TOP_N);
const labels=sortedMitre.map(x=>x[0].split(' - ')[0]);
const data=sortedMitre.map(x=>x[1]);
const bgColors=['#f85149','#db6d28','#d29922','#3fb950','#58a6ff','#bc8cff','#f0883e','#56d364','#79c0ff','#d2a8ff'];

if(mitreChart)mitreChart.destroy();
const ctx=document.getElementById('mitreChart').getContext('2d');
mitreChart=new Chart(ctx,{
type:'bar',
data:{labels:labels,datasets:[{label:'Occurrences',data:data,backgroundColor:bgColors,borderWidth:0}]},
options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{beginAtZero:true,ticks:{precision:0}}}}
});
}

function filterMitreTechniques(){
const search=document.getElementById('mitreSearch').value.toUpperCase();
const cards=document.querySelectorAll('.mc-card');
cards.forEach(card=>{
const text=card.textContent.toUpperCase();
card.style.display=text.includes(search)?'block':'none';
});
}

function searchMitre(techniqueId){
openMitreModal();
setTimeout(()=>{
document.getElementById('mitreSearch').value=techniqueId;
filterMitreTechniques();
},100);
}

function openChatGPT(url,title){
window.open('https://chatgpt.com/?q='+encodeURIComponent('Please analyze this cybersecurity article "'+title+'" and provide a professional, well-structured, technically accurate summary. Include: 1. Executive Summary 2. Key Technical Details 3. Threat Actor/Campaign Information (if applicable) 4. Impact and Risk Assessment 5. MITRE ATT&CK Techniques (if detected) 6. Recommended Mitigations with example. Article URL: '+url),'_blank');
}

function openClaude(url,title){
window.open('https://claude.ai/new?q='+encodeURIComponent('Please analyze this cybersecurity article "'+title+'" and provide a professional, well-structured, technically accurate summary. Include: 1. Executive Summary 2. Key Technical Details 3. Threat Actor/Campaign Information (if applicable) 4. Impact and Risk Assessment 5. MITRE ATT&CK Techniques (if detected) 6. Recommended Mitigations with example. Article URL: '+url),'_blank');
}

function openGemini(url,title){
const prompt='Please analyze this cybersecurity article "'+title+'" and provide a professional, well-structured, technically accurate summary. Include: 1. Executive Summary 2. Key Technical Details 3. Threat Actor/Campaign Information (if applicable) 4. Impact and Risk Assessment 5. MITRE ATT&CK Techniques (if detected) 6. Recommended Mitigations with example. Article URL: '+url;
navigator.clipboard.writeText(prompt).then(()=>{
window.open('https://gemini.google.com/app','_blank');
alert('Prompt copied to clipboard! Paste it in Gemini (Ctrl+V or Cmd+V).');
}).catch(()=>{
window.open('https://gemini.google.com/app','_blank');
});
}

async function openVulnModal(){
document.getElementById('vulnModal').style.display='block';
document.getElementById('vulnLoading').style.display='block';
document.getElementById('vulnContent').style.display='none';
activeSeverityFilter='ALL';
await fetchVulnerabilities();
}

function closeVulnModal(){
document.getElementById('vulnModal').style.display='none';
}

async function fetchVulnerabilities(){
try{
const endDate=new Date();
const startDate=new Date();
startDate.setDate(startDate.getDate()-VULN_DAYS);

const startStr=startDate.toISOString().split('T')[0]+'T00:00:00.000';
const endStr=endDate.toISOString().split('T')[0]+'T23:59:59.999';

const url='https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate='+startStr+'&pubEndDate='+endStr;

const response=await fetch(url);
const data=await response.json();

if(data.vulnerabilities){
allVulnData=data.vulnerabilities.map(v=>{
const cve=v.cve;
const metrics=cve.metrics;
let severity='UNKNOWN';
let score=0;

if(metrics?.cvssMetricV31&&metrics.cvssMetricV31.length>0){
severity=metrics.cvssMetricV31[0].cvssData.baseSeverity||'UNKNOWN';
score=metrics.cvssMetricV31[0].cvssData.baseScore||0;
}else if(metrics?.cvssMetricV3&&metrics.cvssMetricV3.length>0){
severity=metrics.cvssMetricV3[0].cvssData.baseSeverity||'UNKNOWN';
score=metrics.cvssMetricV3[0].cvssData.baseScore||0;
}else if(metrics?.cvssMetricV2&&metrics.cvssMetricV2.length>0){
severity=metrics.cvssMetricV2[0].baseSeverity||'UNKNOWN';
score=metrics.cvssMetricV2[0].cvssData.baseScore||0;
}

const desc=cve.descriptions?.find(d=>d.lang==='en')?.value||'No description available';

return{
id:cve.id,
published:new Date(cve.published),
severity:severity,
score:score,
description:desc
};
});

filteredVulnData=[...allVulnData];
displayVulnData();
}else{
document.getElementById('vulnLoading').innerHTML='<p>No vulnerabilities found.</p>';
}
}catch(err){
document.getElementById('vulnLoading').innerHTML='<p style="color:red">Error loading data: '+escapeHtml(err.message)+'</p>';
}
}

function displayVulnData(){
document.getElementById('vulnLoading').style.display='none';
document.getElementById('vulnContent').style.display='block';

const stats={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
filteredVulnData.forEach(v=>{
if(stats.hasOwnProperty(v.severity))stats[v.severity]++;
});

document.getElementById('criticalCount').textContent=stats.CRITICAL;
document.getElementById('highCount').textContent=stats.HIGH;
document.getElementById('mediumCount').textContent=stats.MEDIUM;
document.getElementById('lowCount').textContent=stats.LOW;

updateVulnChart(stats);
renderVulnTable();
}

function updateVulnChart(stats){
const labels=['Critical','High','Medium','Low'];
const data=[stats.CRITICAL,stats.HIGH,stats.MEDIUM,stats.LOW];
const bgColors=['#e74c3c','#f39c12','#f1c40f','#27ae60'];

if(vulnChart)vulnChart.destroy();
const ctx=document.getElementById('vulnChart').getContext('2d');
vulnChart=new Chart(ctx,{
type:'bar',
data:{labels:labels,datasets:[{label:'Vulnerabilities',data:data,backgroundColor:bgColors,borderWidth:0}]},
options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{y:{beginAtZero:true,ticks:{precision:0}}}}
});
}

function renderVulnTable(){
const tbody=document.getElementById('vulnTableBody');
tbody.innerHTML='';

const sortedData=[...filteredVulnData].sort((a,b)=>b.published-a.published);

sortedData.forEach(v=>{
const row=tbody.insertRow();
const dateStr=v.published.toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'});
const sevClass='sev-'+v.severity.toLowerCase().charAt(0);
const cveUrl='https://nvd.nist.gov/vuln/detail/'+escapeHtml(v.id);
const displaySeverity=v.severity==='UNKNOWN'?'N/A':escapeHtml(v.severity);
const scoreDisplay=v.score>0?'<span class="scr scr-'+v.severity.toLowerCase().charAt(0)+'">'+v.score.toFixed(1)+'</span>':'<span style="color:var(--dim)">-</span>';
row.innerHTML='<td><a href="'+cveUrl+'" target="_blank" style="font-weight:700">'+escapeHtml(v.id)+'</a></td><td>'+escapeHtml(dateStr)+'</td><td><span class="sev '+sevClass+'">'+displaySeverity+'</span></td><td>'+scoreDisplay+'</td><td>'+escapeHtml(v.description)+'</td>';
});
}

function filterBySeverity(severity){
document.querySelectorAll('.vc-stat').forEach(c=>c.classList.remove('on'));
if(activeSeverityFilter===severity){
activeSeverityFilter='ALL';
filteredVulnData=[...allVulnData];
}else{
activeSeverityFilter=severity;
filteredVulnData=allVulnData.filter(v=>v.severity===severity);
event.currentTarget.classList.add('on');
}
displayVulnData();
}

function filterVulnTable(){
const search=document.getElementById('vulnSearch').value.toUpperCase();
if(!search){
filteredVulnData=activeSeverityFilter==='ALL'?[...allVulnData]:allVulnData.filter(v=>v.severity===activeSeverityFilter);
}else{
const baseData=activeSeverityFilter==='ALL'?allVulnData:allVulnData.filter(v=>v.severity===activeSeverityFilter);
filteredVulnData=baseData.filter(v=>v.id.toUpperCase().includes(search)||v.description.toUpperCase().includes(search));
}
renderVulnTable();
}

window.onclick=function(event){
if(event.target==document.getElementById('mitreModal')){
closeMitreModal();
}
if(event.target==document.getElementById('vulnModal')){
closeVulnModal();
}
}

window.onload=()=>{
loadTheme();
filterData();
renderFeedHealth();
document.getElementById('totalCount').textContent=allData.length;
const newItemsCount=allData.filter(x=>x.new).length;
document.getElementById('newCount').textContent=newItemsCount;
document.getElementById('mitreCount').textContent=Object.keys(mitreData).length;
updateSourceDistribution();
setTimeout(()=>{document.getElementById('searchInput').focus()},100);
};
</script>
<button class="btt" id="backToTop" onclick="window.scrollTo({top:0,behavior:'smooth'})">&#x2191;</button>
</body>
</html>
"@

    [System.IO.File]::WriteAllText($HtmlPath, $HtmlContent, [System.Text.UTF8Encoding]::new($false))
    
    # Copy local Chart.js library alongside report
    $libSource = Join-Path $PSScriptRoot "lib"
    $libDest = Join-Path $OutputDir "lib"
    if ((Test-Path $libSource) -and $OutputDir -ne $PSScriptRoot) {
        if (-not (Test-Path $libDest)) { New-Item -ItemType Directory -Path $libDest -Force | Out-Null }
        Copy-Item (Join-Path $libSource "chart.min.js") $libDest -Force
    }
    
    # Copy logo alongside report
    $logoSrc = Join-Path $PSScriptRoot "assets\logo.png"
    $logoDestDir = Join-Path $OutputDir "assets"
    if ((Test-Path $logoSrc) -and $OutputDir -ne $PSScriptRoot) {
        if (-not (Test-Path $logoDestDir)) { New-Item -ItemType Directory -Path $logoDestDir -Force | Out-Null }
        Copy-Item $logoSrc $logoDestDir -Force
    }
    
    Write-Log "HTML report generated: $HtmlPath" -Level Info
    Write-Host "`n[OK] Report generated successfully!" -ForegroundColor Green
    Write-Host "CSV: $CsvPath" -ForegroundColor Cyan
    Write-Host "HTML: $HtmlPath" -ForegroundColor Cyan
    Write-Host "Log: $script:LogFile" -ForegroundColor Cyan
    if ($ExportHealthReport) {
        Write-Host "Health Report: $HealthReportPath" -ForegroundColor Cyan
    }
    Write-Host "Config Snapshot: $ConfigSnapshotPath" -ForegroundColor Cyan
    Write-Host "`nSummary:" -ForegroundColor Yellow
    Write-Host "  New links found:    $NewLinksCount" -ForegroundColor Green
    Write-Host "  Duplicates skipped: $DuplicatesSkipped" -ForegroundColor Yellow
    Write-Host "  Total in report:    $($AllResultsForCSV.Count)" -ForegroundColor Cyan
    Write-Host "  MITRE Techniques:   $($MitreStats.Count)" -ForegroundColor Magenta
    Write-Host "  Processing Time:    $([math]::Round($TotalDuration, 2))s" -ForegroundColor Cyan
    if (-not $NoOpenReport) {
        Write-Host "`nOpening HTML report..." -ForegroundColor Yellow
        Start-Process $HtmlPath
    } else {
        Write-Host "`nHTML report ready: $HtmlPath" -ForegroundColor Yellow
    }
}
catch {
    Write-Log "Critical error: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    throw
}
