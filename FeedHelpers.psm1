# ============================================================
# FeedHelpers.psm1 — Shared helper functions for ThreatRaven.ps1
# Version: 3.0
# ============================================================

#Requires -Version 5.1

function Get-AllTextContent {
    <#
    .SYNOPSIS
        Extracts and combines text content from RSS/Atom feed items.
    .DESCRIPTION
        Parses XML feed items and extracts text from title, description,
        content, and other fields. Strips HTML tags and decodes entities.
    .PARAMETER Item
        The feed item (XmlElement or PSCustomObject) to extract text from.
    .OUTPUTS
        [string] Combined text content with HTML stripped.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Item
    )
    
    $textParts = [System.Collections.Generic.List[string]]::new()
    
    $fieldsToCheck = @(
        'title', 'description', 'summary', 'content',
        'encoded', 'contentEncoded', 'content:encoded',
        '#text', 'subtitle', 'rights', 'category'
    )
    
    foreach ($field in $fieldsToCheck) {
        try {
            if ($Item.PSObject.Properties[$field]) {
                $value = $Item.$field
                if ($value -is [string] -and $value.Trim() -ne '') {
                    $textParts.Add($value)
                }
                elseif ($value -is [System.Xml.XmlElement]) {
                    $textParts.Add($value.InnerText)
                }
                elseif ($value -is [array]) {
                    foreach ($v in $value) {
                        if ($v -is [string])    { $textParts.Add($v) }
                        elseif ($v.InnerText)   { $textParts.Add($v.InnerText) }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Error reading field '$field': $($_.Exception.Message)"
        }
    }
    
    try {
        if ($Item.'content:encoded') { 
            $textParts.Add($Item.'content:encoded') 
        }
    }
    catch { }
    
    if ($textParts.Count -eq 0) {
        return [string]::Empty
    }
    
    $combined = $textParts -join ' '
    
    # Strip HTML tags and decode entities in single pass
    $combined = $combined -replace '<[^>]+>', ' '
    $combined = $combined -replace '&nbsp;', ' '
    $combined = $combined -replace '&amp;', '&'
    $combined = $combined -replace '&lt;', '<'
    $combined = $combined -replace '&gt;', '>'
    $combined = $combined -replace '&quot;', '"'
    $combined = $combined -replace '&#39;', "'"
    $combined = $combined -replace '&#x27;', "'"
    $combined = $combined -replace '&#x2F;', '/'
    $combined = $combined -replace '\s+', ' '
    
    return $combined.Trim()
}

function Get-ItemLink {
    <#
    .SYNOPSIS
        Extracts the article link from an RSS/Atom feed item.
    .DESCRIPTION
        Handles special cases for specific feeds (Reddit, CISA, etc.)
        and falls back to standard RSS/Atom link extraction.
    .PARAMETER Item
        The feed item to extract the link from.
    .PARAMETER FeedUrl
        The URL of the feed source (used for special handling).
    .OUTPUTS
        [string] The extracted link or the feed URL as fallback.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Item,
        
        [Parameter(Mandatory)]
        [string]$FeedUrl
    )
    
    $extractedLink = $null
    
    # Helper to safely get text from various property types
    $getText = {
        param($Prop)
        if ($Prop -is [string]) { return $Prop }
        elseif ($Prop.'#text')  { return $Prop.'#text' }
        elseif ($Prop.href)     { return $Prop.href }
        elseif ($Prop.InnerText) { return $Prop.InnerText }
        return $null
    }
    
    # 0patch.com special handling
    if ($FeedUrl -match '0patch\.com') {
        if ($Item.link -and $Item.link -is [string] -and
            $Item.link -match '^https?://blog\.0patch\.com/\d{4}/\d{2}/' -and
            $Item.link -notmatch '/feeds/|/comments/') {
            return $Item.link.Trim()
        }
        if ($Item.guid) {
            $guidText = & $getText $Item.guid
            if ($guidText -match '^https?://blog\.0patch\.com/\d{4}/\d{2}/[^/]+\.html') {
                return $guidText.Trim()
            }
        }
        $contentToSearch = ''
        if ($Item.content)     { $contentToSearch += & $getText $Item.content }
        if ($Item.description) { $contentToSearch += ' ' + (& $getText $Item.description) }
        if ($contentToSearch -match 'href="(https?://blog\.0patch\.com/\d{4}/\d{2}/[^"]+\.html)"') {
            return $matches[1].Trim()
        }
    }
    
    # any.run special handling
    if ($FeedUrl -match 'any\.run') {
        if ($Item.link) {
            $extractedLink = & $getText $Item.link
        }
        if (-not $extractedLink -and $Item.guid) {
            $extractedLink = & $getText $Item.guid
        }
        if (-not $extractedLink -and $Item.id) {
            $extractedLink = $Item.id
        }
        
        if ($extractedLink) {
            if     ($extractedLink -match '^/')                  { $extractedLink = "https://any.run$extractedLink" }
            elseif ($extractedLink -match '^cybersecurity-blog') { $extractedLink = "https://any.run/$extractedLink" }
            elseif ($extractedLink -match '^\?p=')               { $extractedLink = "https://any.run/cybersecurity-blog/$extractedLink" }
            
            if ($extractedLink -match '^https?://any\.run/' -and $extractedLink -notmatch '\.xml$|/feed/?$') {
                return $extractedLink.Trim()
            }
        }
        
        $contentToSearch = ''
        if ($Item.description) { $contentToSearch += & $getText $Item.description }
        if ($Item.content)     { $contentToSearch += ' ' + (& $getText $Item.content) }
        if ($contentToSearch -match 'href="(https?://any\.run/[^"]+)"') {
            return $matches[1].Trim()
        }
    }
    
    # Reddit special handling
    if ($FeedUrl -match 'reddit\.com') {
        $redditPostLink = $null
        
        if ($Item.link -and $Item.link -match 'reddit\.com/r/[^/]+/comments/') {
            $redditPostLink = $Item.link
        }
        elseif ($Item.id -and $Item.id -match 'reddit\.com/r/[^/]+/comments/') {
            $redditPostLink = $Item.id
        }
        elseif ($Item.guid) {
            $gv = & $getText $Item.guid
            if ($gv -match 'reddit\.com/r/[^/]+/comments/') { 
                $redditPostLink = $gv 
            }
        }
        
        if (-not $redditPostLink) {
            $contentToSearch = ''
            if ($Item.content)     { $contentToSearch += & $getText $Item.content }
            if ($Item.description) { $contentToSearch += ' ' + (& $getText $Item.description) }
            
            if ($contentToSearch) {
                if ($contentToSearch -match 'href="(https?://[^"]*reddit\.com/r/[^/]+/comments/[^"]*)"') {
                    $redditPostLink = $matches[1].Trim()
                }
                elseif ($contentToSearch -match '(https?://[^\s<>"]*reddit\.com/r/[^/]+/comments/[^\s<>"]*)') {
                    $redditPostLink = $matches[1].Trim()
                }
            }
        }
        
        if ($redditPostLink) { return $redditPostLink.Trim() }
        return $null
    }
    
    # Standard link extraction
    $linkSources = @(
        { $Item.link },
        { $Item.guid },
        { $Item.id },
        { $Item.url },
        { $Item.'feedburner:origLink' },
        { $Item.origLink }
    )
    
    foreach ($source in $linkSources) {
        try {
            $value = & $source
            if ($value) {
                $candidate = $null
                
                if     ($value -is [string]) { $candidate = $value }
                elseif ($value.href)         { $candidate = $value.href }
                elseif ($value.'#text')      { $candidate = $value.'#text' }
                elseif ($value.InnerText)    { $candidate = $value.InnerText }
                elseif ($value -is [array]) {
                    foreach ($linkItem in $value) {
                        $c = if ($linkItem -is [string]) { $linkItem }
                             elseif ($linkItem.href)     { $linkItem.href }
                             else { $null }
                        
                        if ($c -and $c -match '^https?://' -and 
                            $c -notmatch '\.xml$|/feed/?$|/rss/?$|/feeds/|/comments/') {
                            $candidate = $c
                            break
                        }
                    }
                }
                
                if ($candidate -and $candidate -match '^https?://' -and
                    $candidate -notmatch '\.xml$|/feed/?$|/rss/?$|/feeds/|/comments/') {
                    $extractedLink = $candidate
                    break
                }
            }
        }
        catch {
            Write-Verbose "Error extracting link from source: $($_.Exception.Message)"
        }
    }
    
    # CISA special handling
    if ((-not $extractedLink -or $extractedLink -eq $FeedUrl) -and $FeedUrl -match 'cisa\.gov') {
        if ($Item.id -or $Item.guid) {
            $advisoryId = if ($Item.id) { $Item.id } else { $Item.guid }
            if ($advisoryId -match '(AA|ICSA?|ICS-?ALERT|CSAF)-\d{2}-\d{3,6}') {
                $extractedLink = "https://www.cisa.gov/news-events/cybersecurity-advisories/$advisoryId"
            }
        }
    }
    
    # Talos special handling
    if ((-not $extractedLink -or $extractedLink -eq $FeedUrl) -and $FeedUrl -match 'talosintelligence|feedburner/Talos') {
        if ($Item.description -match 'href="(https?://[^"]+)"') {
            $extractedLink = $matches[1]
        }
    }
    
    # Fallback
    if (-not $extractedLink -or
        $extractedLink -match '\.xml$|/feed/?$|/rss/?$|/feeds/.*comments|/comments/' -or
        $extractedLink -eq $FeedUrl) {
        $extractedLink = $FeedUrl
    }
    
    return $extractedLink.Trim()
}

function Test-UrlSafety {
    <#
    .SYNOPSIS
        Validates a URL against security patterns.
    .DESCRIPTION
        Checks URL scheme, format, and against allowed patterns
        to prevent potential security issues.
    .PARAMETER Url
        The URL to validate.
    .PARAMETER AllowedPatterns
        Array of regex patterns that the URL must match.
    .OUTPUTS
        [bool] True if URL is safe, False otherwise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        
        [string[]]$AllowedPatterns = @("^https?://")
    )
    
    if ([string]::IsNullOrWhiteSpace($Url)) {
        return $false
    }
    
    try {
        $uri = [System.Uri]$Url
        if ($uri.Scheme -notin @('http', 'https')) {
            Write-Verbose "URL rejected (invalid scheme: $($uri.Scheme)): $Url"
            return $false
        }
        
        # Block common malicious patterns
        if ($Url -match 'javascript:|data:|file:|ftp:|<script|<iframe|onerror=|onload=') {
            Write-Verbose "URL rejected (malicious pattern): $Url"
            return $false
        }
    }
    catch {
        Write-Verbose "URL rejected (invalid URI): $Url"
        return $false
    }
    
    foreach ($pattern in $AllowedPatterns) {
        if ($Url -match $pattern) {
            return $true
        }
    }
    
    Write-Verbose "URL rejected (no matching pattern): $Url"
    return $false
}

function ConvertTo-HtmlEscaped {
    <#
    .SYNOPSIS
        Escapes a string for safe HTML insertion.
    .DESCRIPTION
        Converts special characters to HTML entities to prevent XSS attacks.
    .PARAMETER Text
        The text to escape.
    .OUTPUTS
        [string] HTML-escaped text.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text
    )
    
    if ([string]::IsNullOrEmpty($Text)) {
        return [string]::Empty
    }
    
    $escaped = $Text
    $escaped = $escaped -replace '&', '&amp;'
    $escaped = $escaped -replace '<', '&lt;'
    $escaped = $escaped -replace '>', '&gt;'
    $escaped = $escaped -replace '"', '&quot;'
    $escaped = $escaped -replace "'", '&#39;'
    $escaped = $escaped -replace '/', '&#x2F;'
    
    return $escaped
}

function ConvertTo-JavaScriptString {
    <#
    .SYNOPSIS
        Escapes a string for safe JavaScript string insertion.
    .DESCRIPTION
        Converts special characters to JavaScript escape sequences.
    .PARAMETER Text
        The text to escape.
    .OUTPUTS
        [string] JavaScript-safe string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text
    )
    
    if ([string]::IsNullOrEmpty($Text)) {
        return [string]::Empty
    }
    
    $escaped = $Text
    $escaped = $escaped -replace '\\', '\\\\'
    $escaped = $escaped -replace '"', '\"'
    $escaped = $escaped -replace "'", "\'"
    $escaped = $escaped -replace "`n", ' '
    $escaped = $escaped -replace "`r", ''
    $escaped = $escaped -replace '</script', '<\/script'
    
    return $escaped
}

function Get-FeedHealthReport {
    <#
    .SYNOPSIS
        Generates a health report for monitored feeds.
    .DESCRIPTION
        Analyzes feed health data and returns a structured report.
    .PARAMETER FeedHealth
        ConcurrentDictionary containing feed health data.
    .OUTPUTS
        [PSCustomObject] Health report with statistics.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Concurrent.ConcurrentDictionary[string,PSObject]]$FeedHealth
    )
    
    $healthy = 0
    $degraded = 0
    $unhealthy = 0
    $totalSuccess = 0
    $totalFailures = 0
    $unhealthyList = [System.Collections.Generic.List[PSObject]]::new()
    
    foreach ($entry in $FeedHealth.GetEnumerator()) {
        $host_ = $entry.Key
        $health = $entry.Value
        
        $totalSuccess += $health.SuccessCount
        $totalFailures += $health.FailureCount
        
        if ($health.FailureCount -gt 0 -and $health.SuccessCount -eq 0) {
            $unhealthy++
            $unhealthyList.Add([PSCustomObject]@{
                Host = $host_
                Status = 'UNHEALTHY'
                Failures = $health.FailureCount
                LastError = $health.LastError
                LastChecked = $health.LastChecked
            })
        }
        elseif ($health.FailureCount -gt 2) {
            $degraded++
            $unhealthyList.Add([PSCustomObject]@{
                Host = $host_
                Status = 'DEGRADED'
                Failures = $health.FailureCount
                LastError = $health.LastError
                LastChecked = $health.LastChecked
            })
        }
        else {
            $healthy++
        }
    }
    
    return [PSCustomObject]@{
        Healthy = $healthy
        Degraded = $degraded
        Unhealthy = $unhealthy
        TotalSuccess = $totalSuccess
        TotalFailures = $totalFailures
        UnhealthyFeeds = $unhealthyList
        Timestamp = Get-Date
    }
}

function Export-FeedHealthReport {
    <#
    .SYNOPSIS
        Exports feed health data to a JSON file.
    .DESCRIPTION
        Saves feed health metrics for historical tracking.
    .PARAMETER FeedHealth
        ConcurrentDictionary containing feed health data.
    .PARAMETER Path
        Output file path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Concurrent.ConcurrentDictionary[string,PSObject]]$FeedHealth,
        
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    $report = Get-FeedHealthReport -FeedHealth $FeedHealth
    
    $exportData = [PSCustomObject]@{
        GeneratedAt = $report.Timestamp
        Summary = [PSCustomObject]@{
            Healthy = $report.Healthy
            Degraded = $report.Degraded
            Unhealthy = $report.Unhealthy
            TotalSuccess = $report.TotalSuccess
            TotalFailures = $report.TotalFailures
        }
        Feeds = @()
    }
    
    foreach ($entry in $FeedHealth.GetEnumerator()) {
        $exportData.Feeds += [PSCustomObject]@{
            Host = $entry.Key
            SuccessCount = $entry.Value.SuccessCount
            FailureCount = $entry.Value.FailureCount
            TotalItems = $entry.Value.TotalItems
            TotalMatches = $entry.Value.TotalMatches
            LastError = $entry.Value.LastError
            LastChecked = $entry.Value.LastChecked
        }
    }
    
    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
    Write-Verbose "Feed health report exported to: $Path"
}

function Save-RunConfiguration {
    <#
    .SYNOPSIS
        Saves the current run configuration for audit purposes.
    .PARAMETER Config
        The configuration object.
    .PARAMETER Path
        Output file path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config,
        
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    $runConfig = [PSCustomObject]@{
        Timestamp = Get-Date
        Settings = $Config.Settings
        FeedCount = $Config.Feeds.Count
        KeywordCount = $Config.Keywords.Count
        MitreTechniqueCount = $Config.MitreKeywords.PSObject.Properties.Name.Count
    }
    
    $runConfig | ConvertTo-Json -Depth 5 | Out-File -FilePath $Path -Encoding UTF8
}

function Test-Configuration {
    <#
    .SYNOPSIS
        Validates the configuration file has all required fields.
    .DESCRIPTION
        Checks for required fields, non-empty arrays, and valid setting values.
    .PARAMETER Config
        The configuration object to validate.
    .OUTPUTS
        [bool] True if configuration is valid.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config
    )
    
    $requiredFields = @('Settings', 'Keywords', 'MitreKeywords', 'Feeds', 'UserAgents')
    $missingFields = @()
    
    foreach ($field in $requiredFields) {
        if (-not $Config.PSObject.Properties[$field]) {
            $missingFields += $field
        }
    }
    
    if ($missingFields.Count -gt 0) {
        throw "Configuration missing required fields: $($missingFields -join ', ')"
    }
    
    if ($Config.Keywords.Count -eq 0) {
        throw "Configuration Keywords array is empty"
    }
    
    if ($Config.Feeds.Count -eq 0) {
        throw "Configuration Feeds array is empty"
    }
    
    if ($Config.UserAgents.Count -eq 0) {
        throw "Configuration UserAgents array is empty"
    }
    
    if ($null -ne $Config.Settings.ThrottleLimit -and $Config.Settings.ThrottleLimit -lt 1) {
        throw "ThrottleLimit must be greater than 0"
    }
    
    if ($null -ne $Config.Settings.MaxRetries -and $Config.Settings.MaxRetries -lt 1) {
        throw "MaxRetries must be greater than 0"
    }
    
    Write-Verbose "Configuration validation passed"
    return $true
}

function Initialize-Configuration {
    <#
    .SYNOPSIS
        Loads and validates the configuration file.
    .DESCRIPTION
        Reads a JSON config file, validates its structure, and returns the parsed config.
    .PARAMETER Path
        Path to the JSON configuration file.
    .OUTPUTS
        [PSCustomObject] The parsed and validated configuration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    if (-not (Test-Path $Path)) {
        throw "Configuration file not found at: $Path"
    }
    
    try {
        $config = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        Test-Configuration -Config $config | Out-Null
        return $config
    }
    catch {
        throw "Failed to parse configuration: $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function @(
    'Get-AllTextContent',
    'Get-ItemLink',
    'Test-UrlSafety',
    'ConvertTo-HtmlEscaped',
    'ConvertTo-JavaScriptString',
    'Get-FeedHealthReport',
    'Export-FeedHealthReport',
    'Save-RunConfiguration',
    'Test-Configuration',
    'Initialize-Configuration'
)
