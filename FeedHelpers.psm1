# ============================================================
# FeedHelpers.psm1 - Shared helper functions for ThreatRaven.ps1
# Version: 5.0
#
# v5.0 changes:
#  - HttpClient-based fetching (Invoke-FeedRequest): gzip/deflate on
#    PowerShell 5.1, hard response-size cap, streaming read, identical
#    behaviour on PS 5.1 and 7+
#  - Retry state machine (Invoke-FeedFetchWithRetry / Get-HttpStatusAction):
#    UA rotation only on 403/406, DNS/TLS failures not retried, bounded
#    request count per feed, Retry-After honoured
#  - All dates normalised to UTC (RFC1123 "GMT" dates were previously left
#    unconverted while offset dates were converted to local time)
#  - Match timeouts on every content regex
#  - Feed definitions: strings or {Url, Name, Category} objects
#  - CVE ID extraction, CISA KEV and FIRST EPSS enrichment, CVSS 4.0
#  - Feed health status derived from run history (degraded is reachable)
#  - Corrupt state is preserved as .corrupt-<ts> and the .bak is tried
#  - Items without a resolvable link are skipped instead of collapsing
#    onto the feed URL
#  - ConvertTo-EmbeddedJson for report data (no hand-rolled JS escaping)
#  - Environment overrides: THREATRAVEN_NVD_API_KEY, THREATRAVEN_WEBHOOK_URL
# ============================================================

#Requires -Version 5.1

if (-not ('System.Net.Http.HttpClient' -as [type])) {
    Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
}

$script:RegexTimeout = [TimeSpan]::FromSeconds(2)
$script:RxCI = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
$script:RxNone = [System.Text.RegularExpressions.RegexOptions]::None
$script:CveRegex = [regex]::new('\bCVE-\d{4}-\d{4,7}\b', $script:RxCI, $script:RegexTimeout)
$script:MitreIdRegex = [regex]::new('\bT\d{4}(?:\.\d{3})?\b', $script:RxNone, $script:RegexTimeout)
$script:HtmlTagRegex = [regex]::new('<[^>]*>', $script:RxNone, $script:RegexTimeout)
$script:WhitespaceRegex = [regex]::new('\s+', $script:RxNone, $script:RegexTimeout)
$script:FeedHttpClient = $null
$script:FeedHttpClientSkipCert = $null

# ------------------------------------------------------------
# Generic helpers
# ------------------------------------------------------------
function Get-ObjectProperty {
    <#
    .SYNOPSIS
        Strict-mode safe property accessor for XML items / PSCustomObjects.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        $Item,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Item) { return $null }
    $prop = $Item.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Get-RegexMatch {
    <#
    .SYNOPSIS
        Case-insensitive regex match with a timeout; returns the Match or $null.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()]
        [string]$Text,

        [Parameter(Mandatory)]
        [string]$Pattern
    )

    if ([string]::IsNullOrEmpty($Text)) { return $null }
    try {
        $m = [regex]::Match($Text, $Pattern, $script:RxCI, $script:RegexTimeout)
        if ($m.Success) { return $m }
    }
    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
        Write-Verbose "Regex timed out: $Pattern"
    }
    return $null
}

function Get-CveIdsFromText {
    <#
    .SYNOPSIS
        Extracts unique, upper-cased CVE identifiers from free text.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()]
        [string]$Text
    )

    if ([string]::IsNullOrEmpty($Text)) { return @() }
    $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    try {
        foreach ($m in $script:CveRegex.Matches($Text)) { $null = $set.Add($m.Value.ToUpperInvariant()) }
    }
    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { }
    return @($set | Sort-Object)
}

function Get-MitreIdsFromText {
    <#
    .SYNOPSIS
        Extracts explicit ATT&CK technique IDs (T1234 / T1234.001) from text.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()]
        [string]$Text
    )

    if ([string]::IsNullOrEmpty($Text)) { return @() }
    $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    try {
        foreach ($m in $script:MitreIdRegex.Matches($Text)) { $null = $set.Add($m.Value.ToUpperInvariant()) }
    }
    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { }
    return @($set | Sort-Object)
}

# ------------------------------------------------------------
# Dates
# ------------------------------------------------------------
function ConvertTo-DateTime {
    <#
    .SYNOPSIS
        Parses a feed date string and returns a UTC DateTime.
    .DESCRIPTION
        Uses invariant culture with AssumeUniversal/AdjustToUniversal so an
        RFC1123 "GMT" date, an RFC3339 "Z" date and a "+0200" offset date all
        yield the same instant with Kind=Utc. Common US zone abbreviations are
        mapped to offsets because .NET does not parse them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$InputObject,

        [DateTime]$Fallback = [DateTime]::MinValue
    )

    if ([string]::IsNullOrWhiteSpace($InputObject)) { return $Fallback }

    $ci = [System.Globalization.CultureInfo]::InvariantCulture
    $styles = [System.Globalization.DateTimeStyles]::AllowWhiteSpaces -bor
              [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
              [System.Globalization.DateTimeStyles]::AdjustToUniversal

    $trimmed = $InputObject.Trim()
    # Named US zones -> numeric offsets (RFC822 allows them; .NET does not parse them)
    $zoneMap = @{
        'UT' = '+0000'; 'GMT' = '+0000'; 'UTC' = '+0000'; 'Z' = '+0000'
        'EST' = '-0500'; 'EDT' = '-0400'; 'CST' = '-0600'; 'CDT' = '-0500'
        'MST' = '-0700'; 'MDT' = '-0600'; 'PST' = '-0800'; 'PDT' = '-0700'
        'CET' = '+0100'; 'CEST' = '+0200'; 'BST' = '+0100'; 'IST' = '+0530'; 'JST' = '+0900'
    }
    $zm = [regex]::Match($trimmed, '\s(UT|GMT|UTC|Z|[ECMP][SD]T|CET|CEST|BST|IST|JST)$', $script:RxCI)
    if ($zm.Success) {
        $abbr = $zm.Groups[1].Value.ToUpperInvariant()
        $trimmed = $trimmed.Substring(0, $zm.Index) + ' ' + $zoneMap[$abbr]
    }

    $formats = @(
        'ddd, d MMM yyyy HH:mm:ss zzz',
        'ddd, d MMM yyyy HH:mm:ss zz',
        'ddd, d MMM yyyy HH:mm zzz',
        'd MMM yyyy HH:mm:ss zzz',
        'ddd, d MMM yyyy HH:mm:ss',
        "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK",
        "yyyy-MM-dd'T'HH:mm:ssK",
        "yyyy-MM-dd'T'HH:mmK",
        "yyyy-MM-dd'T'HH:mm:ss",
        'yyyy-MM-dd HH:mm:ss zzz',
        'yyyy-MM-dd HH:mm:ss',
        'yyyy-MM-dd',
        'MM/dd/yyyy HH:mm:ss',
        'ddd MMM d HH:mm:ss yyyy'
    )

    $parsed = [DateTime]::MinValue
    foreach ($f in $formats) {
        if ([DateTime]::TryParseExact($trimmed, $f, $ci, $styles, [ref]$parsed)) {
            return [DateTime]::SpecifyKind($parsed, [DateTimeKind]::Utc)
        }
    }
    if ([DateTime]::TryParse($trimmed, $ci, $styles, [ref]$parsed)) {
        return [DateTime]::SpecifyKind($parsed, [DateTimeKind]::Utc)
    }
    return $Fallback
}

# ------------------------------------------------------------
# Feed item extraction
# ------------------------------------------------------------
function Get-AllTextContent {
    <#
    .SYNOPSIS
        Extracts and combines text content from RSS/Atom feed items.
    .DESCRIPTION
        Parses XML feed items and extracts text from title, description,
        content, and other fields. Strips HTML tags and decodes all
        HTML entities in a single pass via WebUtility.HtmlDecode.
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
        $value = Get-ObjectProperty -Item $Item -Name $field
        if ($null -eq $value) { continue }

        if ($value -is [string]) {
            if ($value.Trim() -ne '') { $textParts.Add($value) }
        }
        elseif ($value -is [System.Xml.XmlElement]) {
            $textParts.Add($value.InnerText)
        }
        elseif ($value -is [System.Collections.IEnumerable]) {
            foreach ($v in $value) {
                if ($v -is [string]) {
                    $textParts.Add($v)
                }
                elseif ($null -ne $v -and $v.PSObject.Properties['InnerText']) {
                    $textParts.Add([string]$v.InnerText)
                }
                elseif ($null -ne $v -and $v.PSObject.Properties['#text']) {
                    $textParts.Add([string]$v.'#text')
                }
            }
        }
    }

    if ($textParts.Count -eq 0) {
        return [string]::Empty
    }

    $combined = $textParts -join ' '
    try {
        $combined = $script:HtmlTagRegex.Replace($combined, ' ')
        $combined = [System.Net.WebUtility]::HtmlDecode($combined)
        $combined = $script:WhitespaceRegex.Replace($combined, ' ')
    }
    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
        $combined = [System.Net.WebUtility]::HtmlDecode($combined)
    }

    return $combined.Trim()
}

function Get-FeedItemTitle {
    <#
    .SYNOPSIS
        Extracts the title of a feed item as plain text (tags stripped, entities decoded).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Item
    )

    $value = Get-ObjectProperty -Item $Item -Name 'title'
    $title = $null

    if ($value -is [string]) {
        $title = $value
    }
    elseif ($null -ne $value -and $value.PSObject.Properties['#text']) {
        $title = [string]$value.'#text'
    }
    elseif ($null -ne $value -and $value.PSObject.Properties['InnerText']) {
        $title = [string]$value.InnerText
    }

    if ([string]::IsNullOrWhiteSpace($title)) { return 'Untitled' }

    try {
        $title = $script:HtmlTagRegex.Replace($title, ' ')
        $title = [System.Net.WebUtility]::HtmlDecode($title)
        $title = $script:WhitespaceRegex.Replace($title, ' ')
    }
    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { }

    $title = $title.Trim()
    if ($title -eq '') { return 'Untitled' }
    return $title
}

function Get-FeedItemDate {
    <#
    .SYNOPSIS
        Parses the publication date of a feed item (UTC).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Item
    )

    $raw = $null
    foreach ($name in @('pubDate', 'published', 'updated', 'dc:date', 'date', 'issued', 'created')) {
        $value = Get-ObjectProperty -Item $Item -Name $name
        if ($null -eq $value) { continue }

        if ($value -is [string]) {
            if (-not [string]::IsNullOrWhiteSpace($value)) { $raw = $value.Trim(); break }
            continue
        }

        $inner = $null
        if ($value.PSObject.Properties['#text']) {
            $inner = [string]$value.'#text'
        }
        elseif ($value.PSObject.Properties['InnerText']) {
            $inner = [string]$value.InnerText
        }
        if (-not [string]::IsNullOrWhiteSpace($inner)) {
            $raw = $inner.Trim()
            break
        }
    }

    if ([string]::IsNullOrWhiteSpace($raw)) {
        return [DateTime]::UtcNow
    }
    $d = ConvertTo-DateTime -InputObject $raw -Fallback ([DateTime]::UtcNow)
    # Clamp absurd future dates (misconfigured feeds) so they don't pin the top of the report
    if ($d -gt [DateTime]::UtcNow.AddDays(2)) { return [DateTime]::UtcNow }
    return $d
}

function Get-ItemLink {
    <#
    .SYNOPSIS
        Extracts the article link from an RSS/Atom feed item.
    .DESCRIPTION
        Handles special cases for specific feeds (Reddit, CISA, 0patch,
        any.run, Talos) and falls back to standard RSS/Atom link extraction
        (preferring rel="alternate" for Atom). Returns $null when no usable
        link exists; callers should skip such items rather than record them
        under the feed URL.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Item,

        [Parameter(Mandatory)]
        [string]$FeedUrl
    )

    $extractedLink = $null
    $feedLike = '\.xml$|/feed/?$|/rss/?$|/feeds/|/comments/'

    $getText = {
        param($Prop)
        if ($null -eq $Prop) { return $null }
        if ($Prop -is [string]) { return $Prop }
        elseif ($Prop.PSObject.Properties['#text']) { return [string]$Prop.'#text' }
        elseif ($Prop.PSObject.Properties['href']) { return [string]$Prop.href }
        elseif ($Prop.PSObject.Properties['InnerText']) { return [string]$Prop.InnerText }
        return $null
    }

    $getSearchText = {
        param($It)
        $s = ''
        foreach ($n in @('content', 'description', 'summary', 'encoded')) {
            $v = Get-ObjectProperty -Item $It -Name $n
            if ($null -ne $v) { $s += ' ' + (& $getText $v) }
        }
        return $s
    }

    # 0patch.com special handling
    if ($FeedUrl -match '0patch\.com') {
        $linkVal = Get-ObjectProperty -Item $Item -Name 'link'
        if ($linkVal -is [string] -and
            $linkVal -match '^https?://blog\.0patch\.com/\d{4}/\d{2}/' -and
            $linkVal -notmatch '/feeds/|/comments/') {
            return $linkVal.Trim()
        }

        $guidVal = Get-ObjectProperty -Item $Item -Name 'guid'
        if ($null -ne $guidVal) {
            $guidText = & $getText $guidVal
            if ($guidText -match '^https?://blog\.0patch\.com/\d{4}/\d{2}/[^/]+\.html') {
                return $guidText.Trim()
            }
        }

        $m = Get-RegexMatch -Text (& $getSearchText $Item) -Pattern 'href="(https?://blog\.0patch\.com/\d{4}/\d{2}/[^"]+\.html)"'
        if ($m) { return $m.Groups[1].Value.Trim() }
    }

    # any.run special handling
    if ($FeedUrl -match 'any\.run') {
        $linkVal = Get-ObjectProperty -Item $Item -Name 'link'
        if ($null -ne $linkVal) { $extractedLink = & $getText $linkVal }

        if (-not $extractedLink) {
            $guidVal = Get-ObjectProperty -Item $Item -Name 'guid'
            if ($null -ne $guidVal) { $extractedLink = & $getText $guidVal }
        }
        if (-not $extractedLink) {
            $idVal = Get-ObjectProperty -Item $Item -Name 'id'
            if ($null -ne $idVal) { $extractedLink = & $getText $idVal }
        }

        if ($extractedLink) {
            if     ($extractedLink -match '^/')                  { $extractedLink = "https://any.run$extractedLink" }
            elseif ($extractedLink -match '^cybersecurity-blog') { $extractedLink = "https://any.run/$extractedLink" }
            elseif ($extractedLink -match '^\?p=')               { $extractedLink = "https://any.run/cybersecurity-blog/$extractedLink" }

            if ($extractedLink -match '^https?://any\.run/' -and $extractedLink -notmatch '\.xml$|/feed/?$') {
                return $extractedLink.Trim()
            }
        }

        $m = Get-RegexMatch -Text (& $getSearchText $Item) -Pattern 'href="(https?://any\.run/[^"]+)"'
        if ($m) { return $m.Groups[1].Value.Trim() }
        $extractedLink = $null
    }

    # Reddit special handling
    if ($FeedUrl -match 'reddit\.com') {
        foreach ($n in @('link', 'id', 'guid')) {
            $v = Get-ObjectProperty -Item $Item -Name $n
            $s = & $getText $v
            if ($s -and $s -match 'reddit\.com/r/[^/]+/comments/') { return $s.Trim() }
        }
        $search = & $getSearchText $Item
        $m = Get-RegexMatch -Text $search -Pattern 'href="(https?://[^"]*reddit\.com/r/[^/"]+/comments/[^"]*)"'
        if ($m) { return $m.Groups[1].Value.Trim() }
        $m = Get-RegexMatch -Text $search -Pattern '(https?://[^\s<>"]{0,80}reddit\.com/r/[^/\s]+/comments/[^\s<>"]*)'
        if ($m) { return $m.Groups[1].Value.Trim() }
        return $null
    }

    # Standard link extraction
    $linkSources = @('link', 'guid', 'id', 'url', 'feedburner:origLink', 'origLink')
    foreach ($sourceName in $linkSources) {
        $value = Get-ObjectProperty -Item $Item -Name $sourceName
        if ($null -eq $value) { continue }

        $candidate = $null
        if ($value -is [string]) {
            $candidate = $value
        }
        elseif ($value.PSObject.Properties['href']) {
            $candidate = [string]$value.href
        }
        elseif ($value.PSObject.Properties['#text']) {
            $candidate = [string]$value.'#text'
        }
        elseif ($value -is [System.Collections.IEnumerable]) {
            # Atom: several <link> elements. Prefer rel="alternate" (or no rel).
            $alternate = $null
            $any = $null
            foreach ($linkItem in $value) {
                $c = $null
                $rel = ''
                if ($linkItem -is [string]) {
                    $c = $linkItem
                }
                elseif ($null -ne $linkItem -and $linkItem.PSObject.Properties['href']) {
                    $c = [string]$linkItem.href
                    if ($linkItem.PSObject.Properties['rel']) { $rel = [string]$linkItem.rel }
                }
                if (-not ($c -and $c -match '^https?://' -and $c -notmatch $feedLike)) { continue }
                if (($rel -eq '' -or $rel -eq 'alternate') -and -not $alternate) { $alternate = $c }
                if (-not $any -and $rel -ne 'self' -and $rel -ne 'replies' -and $rel -ne 'edit' -and $rel -ne 'enclosure') { $any = $c }
            }
            $candidate = if ($alternate) { $alternate } else { $any }
        }
        elseif ($value.PSObject.Properties['InnerText']) {
            $candidate = [string]$value.InnerText
        }

        if ($candidate -and $candidate -match '^https?://' -and $candidate -notmatch $feedLike) {
            $extractedLink = $candidate.Trim()
            break
        }
    }

    # CISA special handling
    if ((-not $extractedLink -or $extractedLink -eq $FeedUrl) -and $FeedUrl -match 'cisa\.gov') {
        $advisoryId = $null
        foreach ($n in @('id', 'guid')) {
            $v = Get-ObjectProperty -Item $Item -Name $n
            if ($null -ne $v) { $advisoryId = & $getText $v; if ($advisoryId) { break } }
        }
        # Real ids look like AA24-131A, ICSA-24-131-01, ICSMA-24-135-01, ICS-ALERT-24-...
        $m = Get-RegexMatch -Text ([string]$advisoryId) -Pattern '\b(AA\d{2}-\d{3}[A-Z]?|ICS[AM]?-\d{2}-\d{3}(?:-\d{2})?|ICS-ALERT-\d{2}-\d{3}(?:-\d{2})?)\b'
        if ($m) {
            $extractedLink = "https://www.cisa.gov/news-events/cybersecurity-advisories/$($m.Groups[1].Value.ToLowerInvariant())"
        }
    }

    # Talos special handling
    if ((-not $extractedLink -or $extractedLink -eq $FeedUrl) -and $FeedUrl -match 'talosintelligence|feedburner/Talos') {
        $dVal = Get-ObjectProperty -Item $Item -Name 'description'
        if ($null -ne $dVal) {
            $m = Get-RegexMatch -Text (& $getText $dVal) -Pattern 'href="(https?://[^"]+)"'
            if ($m) { $extractedLink = $m.Groups[1].Value }
        }
    }

    if (-not $extractedLink -or $extractedLink -eq $FeedUrl -or $extractedLink -match '/feeds/.*comments|/comments/') {
        return $null
    }

    return $extractedLink.Trim()
}

function ConvertTo-NormalizedUrl {
    <#
    .SYNOPSIS
        Normalizes a URL for deduplication.
    .DESCRIPTION
        Lowercases scheme/host, strips fragments and common tracking
        parameters (utm_*, gclid, fbclid, ref, source, etc.), and removes
        trailing slashes from non-root paths.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Url
    )

    if ([string]::IsNullOrWhiteSpace($Url)) { return '' }

    try {
        $uri = [System.Uri]$Url.Trim()
        if ($uri.Scheme -notin @('http', 'https')) { return $Url.Trim() }

        $scheme = $uri.Scheme.ToLowerInvariant()
        $hostName = $uri.Host.ToLowerInvariant()
        $path = $uri.AbsolutePath
        if ($path.Length -gt 1 -and $path.EndsWith('/')) { $path = $path.TrimEnd('/') }

        $query = ''
        if ($uri.Query) {
            $kept = @()
            foreach ($pair in $uri.Query.TrimStart('?').Split('&')) {
                if ($pair -eq '') { continue }
                $name = ($pair -split '=', 2)[0].ToLowerInvariant()
                if ($name -notmatch '^(utm_.*|gclid|fbclid|mc_cid|mc_eid|ref|source|spm|wkey|_hsenc|_hsmi|mkt_tok|oly_.*|yclid|igshid)$') {
                    $kept += $pair
                }
            }
            if ($kept.Count -gt 0) { $query = '?' + ($kept -join '&') }
        }

        return "${scheme}://${hostName}${path}${query}"
    }
    catch {
        return $Url.Trim()
    }
}

function Test-UrlSafety {
    <#
    .SYNOPSIS
        Validates a URL against security patterns.
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

        if ($Url -match '^\s*(javascript|data|vbscript|file|ftp):' -or
            $Url -match '<script|<iframe|onerror=|onload=|["''<>]') {
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

function ConvertTo-JavaScriptString {
    <#
    .SYNOPSIS
        Escapes a string for safe JavaScript string insertion.
    .DESCRIPTION
        Kept for scalar template tokens. Report data is embedded via
        ConvertTo-EmbeddedJson instead.
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
    $escaped = $escaped -replace '\\', '\\'
    $escaped = $escaped -replace '"', '\"'
    $escaped = $escaped -replace "'", "\'"
    $escaped = $escaped.Replace("`r`n", ' ').Replace("`n", ' ').Replace("`r", ' ')
    $escaped = $escaped.Replace([string][char]0x2028, ('\' + 'u2028'))
    $escaped = $escaped.Replace([string][char]0x2029, ('\' + 'u2029'))
    $escaped = $escaped -replace '<', ('\' + 'u003c')
    $escaped = $escaped -replace '>', ('\' + 'u003e')
    $escaped = [regex]::Replace($escaped, '[\x00-\x1F\x7F]', {
        param($m)
        '\u{0:X4}' -f [int][char]$m.Value[0]
    })

    return $escaped
}

function ConvertTo-EmbeddedJson {
    <#
    .SYNOPSIS
        Serializes an object to compact JSON that is safe to embed inside an
        HTML <script type="application/json"> block.
    .DESCRIPTION
        Angle brackets and ampersands are emitted as JSON unicode escapes
        (backslash-u003c etc.) so neither a closing script tag nor an HTML
        comment opener can appear in the output; U+2028/2029 are escaped
        too. JSON.parse yields the original strings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $InputObject,

        [int]$Depth = 6
    )

    $json = ConvertTo-Json -InputObject $InputObject -Depth $Depth -Compress
    if ($null -eq $json) { $json = 'null' }
    $json = $json.Replace('<', ('\' + 'u003c')).Replace('>', ('\' + 'u003e')).Replace('&', ('\' + 'u0026'))
    $json = $json.Replace([string][char]0x2028, ('\' + 'u2028')).Replace([string][char]0x2029, ('\' + 'u2029'))
    return $json
}

# ------------------------------------------------------------
# XML parsing
# ------------------------------------------------------------
function ConvertFrom-FeedContent {
    <#
    .SYNOPSIS
        Parses RSS/Atom/RDF XML safely and returns feed items.
    .DESCRIPTION
        Uses XmlReader with DTD processing ignored, no external resolver,
        and entity/document size limits. Retries once after stripping BOM
        and non-printable control characters. Prefer -Bytes so the
        document's real encoding is honoured.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Text')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Text')]
        [AllowEmptyString()]
        [string]$Content,

        [Parameter(Mandatory, ParameterSetName = 'Bytes')]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    $result = [PSCustomObject]@{
        Items = @()
        Error = $null
    }

    $useBytes = $PSCmdlet.ParameterSetName -eq 'Bytes'

    if ($useBytes) {
        if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
            $result.Error = 'Empty content'
            return $result
        }
        $sniffLen = [Math]::Min(512, $Bytes.Length)
        $head = [System.Text.Encoding]::UTF8.GetString($Bytes, 0, $sniffLen)
        if (($head -replace ('^' + [char]0xFEFF), '').TrimStart() -match '^<(html|!doctype html)') {
            $result.Error = 'Feed returned HTML instead of XML (URL may point to a webpage)'
            return $result
        }
        if (($head -replace ('^' + [char]0xFEFF), '').TrimStart() -match '^[\[{]') {
            $result.Error = 'Feed returned JSON (JSON Feed is not supported)'
            return $result
        }
    }
    else {
        if ([string]::IsNullOrWhiteSpace($Content)) {
            $result.Error = 'Empty content'
            return $result
        }
        if ($Content.TrimStart() -match '^<(html|!doctype html)') {
            $result.Error = 'Feed returned HTML instead of XML (URL may point to a webpage)'
            return $result
        }
    }

    $newSettings = {
        $settings = [System.Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Ignore
        $settings.XmlResolver = $null
        $settings.MaxCharactersFromEntities = 10240
        $settings.MaxCharactersInDocument = 33554432
        $settings.IgnoreWhitespace = $true
        return $settings
    }

    $parse = {
        param([string]$XmlText)
        $reader = [System.Xml.XmlReader]::Create(
            [System.IO.StringReader]::new($XmlText),
            (& $newSettings)
        )
        $doc = [System.Xml.XmlDocument]::new()
        $doc.XmlResolver = $null
        $doc.Load($reader)
        $reader.Dispose()
        return $doc
    }

    $parseStream = {
        param([System.IO.Stream]$Stream)
        $reader = [System.Xml.XmlReader]::Create($Stream, (& $newSettings))
        $doc = [System.Xml.XmlDocument]::new()
        $doc.XmlResolver = $null
        $doc.Load($reader)
        $reader.Dispose()
        return $doc
    }

    $loadItems = {
        param([System.Xml.XmlDocument]$Document)
        $items = @($Document.SelectNodes('//*[local-name()="item"]'))
        if ($items.Count -eq 0) {
            $items = @($Document.SelectNodes('//*[local-name()="entry"]'))
        }
        return $items
    }

    # Lenient repair for the two most common producer bugs: stray control
    # characters and unescaped ampersands (e.g. "?a=1&b=2" inside a URL).
    $repair = {
        param([string]$Text)
        $t = $Text -replace ('^' + [char]0xFEFF), '' -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
        $t = [regex]::Replace($t, '&(?!(?:[A-Za-z][A-Za-z0-9]{1,15}|#\d{1,7}|#x[0-9A-Fa-f]{1,6});)', '&amp;')
        return $t
    }

    $doc = $null
    if ($useBytes) {
        try {
            $ms = [System.IO.MemoryStream]::new($Bytes)
            try { $doc = & $parseStream $ms }
            finally { $ms.Dispose() }
        }
        catch {
            $firstError = $_.Exception.Message
            try {
                $text = [System.Text.Encoding]::UTF8.GetString($Bytes)
                $doc = & $parse (& $repair $text)
            }
            catch {
                $result.Error = "XML parse error: $firstError"
                return $result
            }
        }
    }
    else {
        try {
            $doc = & $parse $Content
        }
        catch {
            $firstError = $_.Exception.Message
            try {
                $doc = & $parse (& $repair $Content)
            }
            catch {
                $result.Error = "XML parse error: $firstError"
                return $result
            }
        }
    }

    $items = @(& $loadItems $doc)
    if ($items.Count -eq 0) {
        $result.Error = 'No items'
    }
    else {
        $result.Items = $items
    }
    return $result
}

# ------------------------------------------------------------
# HTTP
# ------------------------------------------------------------
function Get-WebResponseHeader {
    <#
    .SYNOPSIS
        Reads a response header from a response-like object (dictionary,
        WebHeaderCollection or HttpHeaders) case-insensitively.
    #>
    [CmdletBinding()]
    param(
        $Response,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Response) { return $null }
    # Direct assignment on purpose: `$x = if (...) { $collection }` would
    # enumerate a WebHeaderCollection into its key strings.
    $headers = $null
    if ($Response -is [System.Collections.IDictionary]) { $headers = $Response }
    elseif ($null -ne $Response.PSObject.Properties['Headers']) { $headers = $Response.Headers }
    if ($null -eq $headers) { return $null }

    try {
        if ($headers -is [System.Collections.IDictionary]) {
            foreach ($key in @($headers.Keys)) {
                if ([string]$key -ieq $Name) {
                    $v = $headers[$key]
                    if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { return ([string]($v -join ', ')) }
                    return [string]$v
                }
            }
            return $null
        }

        if ($headers -is [System.Net.WebHeaderCollection]) {
            $value = $headers[$Name]
            if ($null -eq $value) { return $null }
            return [string]$value
        }

        $enumerator = $headers.GetEnumerator()
        while ($enumerator.MoveNext()) {
            if ([string]$enumerator.Current.Key -ieq $Name) {
                $values = $enumerator.Current.Value
                if ($values -is [System.Collections.IEnumerable] -and $values -isnot [string]) {
                    return ([string]($values -join ','))
                }
                return [string]$values
            }
        }
    }
    catch { }

    return $null
}

function Get-FeedHttpClient {
    <#
    .SYNOPSIS
        Returns a shared HttpClient (one per runspace) with decompression and redirects enabled.
    #>
    [CmdletBinding()]
    param(
        [bool]$SkipCertificateValidation = $false
    )

    if ($null -ne $script:FeedHttpClient -and $script:FeedHttpClientSkipCert -eq $SkipCertificateValidation) {
        return $script:FeedHttpClient
    }

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $true
    $handler.MaxAutomaticRedirections = 5
    $handler.UseCookies = $false
    try {
        $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
    }
    catch { }

    if ($SkipCertificateValidation) {
        # .NET Core/5+ (PowerShell 7): the handler ignores ServicePointManager, so use the
        # built-in accept-all validator. On .NET Framework (PS 5.1) the handler goes through
        # HttpWebRequest and honours the compiled ServicePointManager callback set by the script.
        try {
            $acceptAll = [System.Net.Http.HttpClientHandler].GetProperty('DangerousAcceptAnyServerCertificateValidator')
            if ($null -ne $acceptAll) {
                $handler.ServerCertificateCustomValidationCallback = $acceptAll.GetValue($null)
            }
        }
        catch { }
    }

    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan
    $client.MaxResponseContentBufferSize = 268435456

    if ($null -ne $script:FeedHttpClient) { try { $script:FeedHttpClient.Dispose() } catch { } }
    $script:FeedHttpClient = $client
    $script:FeedHttpClientSkipCert = $SkipCertificateValidation
    return $client
}

function Invoke-FeedRequest {
    <#
    .SYNOPSIS
        Performs one GET request with a timeout and a hard response-size cap.
    .OUTPUTS
        PSCustomObject: StatusCode, Headers (case-insensitive dictionary),
        Bytes, Error, ErrorKind ('', 'timeout', 'dns', 'tls', 'toolarge',
        'network'), FinalUrl.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [hashtable]$Headers = @{},

        [int]$TimeoutSeconds = 25,

        [long]$MaxBytes = 10485760,

        [bool]$SkipCertificateValidation = $false
    )

    $result = [PSCustomObject]@{
        StatusCode = 0
        Headers    = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
        Bytes      = $null
        Error      = ''
        ErrorKind  = ''
        FinalUrl   = $Url
    }

    $client = Get-FeedHttpClient -SkipCertificateValidation $SkipCertificateValidation
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Url)
    foreach ($k in $Headers.Keys) {
        $null = $request.Headers.TryAddWithoutValidation([string]$k, [string]$Headers[$k])
    }
    $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds([Math]::Max(1, $TimeoutSeconds)))

    try {
        $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cts.Token).GetAwaiter().GetResult()
        try {
            $result.StatusCode = [int]$response.StatusCode
            if ($null -ne $response.RequestMessage -and $null -ne $response.RequestMessage.RequestUri) {
                $result.FinalUrl = [string]$response.RequestMessage.RequestUri
            }
            foreach ($h in $response.Headers) { $result.Headers[$h.Key] = [string]($h.Value -join ', ') }

            if ($null -ne $response.Content) {
                foreach ($h in $response.Content.Headers) { $result.Headers[$h.Key] = [string]($h.Value -join ', ') }

                $declared = $response.Content.Headers.ContentLength
                if ($null -ne $declared -and $declared -gt $MaxBytes) {
                    $result.Error = "Response too large ($declared bytes; cap $MaxBytes)"
                    $result.ErrorKind = 'toolarge'
                    $result.StatusCode = 0
                    return $result
                }

                if ($result.StatusCode -ne 304) {
                    $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                    try {
                        $buffer = New-Object byte[] 65536
                        $ms = [System.IO.MemoryStream]::new()
                        $total = [long]0
                        while ($true) {
                            $n = $stream.ReadAsync($buffer, 0, $buffer.Length, $cts.Token).GetAwaiter().GetResult()
                            if ($n -le 0) { break }
                            $total += $n
                            if ($total -gt $MaxBytes) {
                                $result.Error = "Response exceeded $MaxBytes bytes"
                                $result.ErrorKind = 'toolarge'
                                $result.StatusCode = 0
                                $ms.Dispose()
                                return $result
                            }
                            $ms.Write($buffer, 0, $n)
                        }
                        $result.Bytes = $ms.ToArray()
                        $ms.Dispose()
                    }
                    finally { $stream.Dispose() }
                }
            }
        }
        finally { $response.Dispose() }
    }
    catch {
        $ex = $_.Exception
        while ($null -ne $ex.InnerException -and ($ex -is [System.AggregateException] -or $ex -is [System.Net.Http.HttpRequestException] -or $ex -is [System.Management.Automation.MethodInvocationException])) {
            $ex = $ex.InnerException
        }
        $msg = $ex.Message
        $result.Error = $msg
        if ($ex -is [System.OperationCanceledException] -or $ex -is [System.TimeoutException]) {
            $result.ErrorKind = 'timeout'
            $result.Error = "Timed out after ${TimeoutSeconds}s"
        }
        elseif ($ex -is [System.Security.Authentication.AuthenticationException] -or $msg -match 'SSL|TLS|certificate|secure channel') {
            $result.ErrorKind = 'tls'
        }
        elseif ($ex -is [System.Net.Sockets.SocketException] -and ($ex.SocketErrorCode -eq 'HostNotFound' -or $ex.SocketErrorCode -eq 'NoData')) {
            $result.ErrorKind = 'dns'
        }
        elseif ($msg -match 'remote name could not be resolved|No such host is known|Name or service not known|nodename nor servname') {
            $result.ErrorKind = 'dns'
        }
        else {
            $result.ErrorKind = 'network'
        }
    }
    finally {
        $cts.Dispose()
        $request.Dispose()
    }

    return $result
}

function Get-HttpStatusAction {
    <#
    .SYNOPSIS
        Classifies a fetch outcome into the action the retry loop should take.
    .OUTPUTS
        'success', 'unchanged', 'ratelimit', 'rotate-ua', 'permanent' or 'retry'.
    #>
    [CmdletBinding()]
    param(
        [int]$StatusCode = 0,

        [string]$ErrorKind = ''
    )

    if ($StatusCode -ge 200 -and $StatusCode -lt 300) { return 'success' }
    if ($StatusCode -eq 304) { return 'unchanged' }
    if ($StatusCode -eq 429) { return 'ratelimit' }
    if ($StatusCode -eq 403 -or $StatusCode -eq 406) { return 'rotate-ua' }
    if ($StatusCode -in @(400, 401, 404, 405, 410, 451)) { return 'permanent' }
    if ($StatusCode -eq 0) {
        if ($ErrorKind -in @('dns', 'tls', 'toolarge')) { return 'permanent' }
        return 'retry'
    }
    return 'retry'
}

function Get-RetryAfterSeconds {
    <#
    .SYNOPSIS
        Parses a Retry-After header (seconds or HTTP-date); 0 when absent/invalid.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()]
        [string]$Value,

        [int]$MaxSeconds = 60
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return 0 }
    $n = 0
    if ([int]::TryParse($Value.Trim(), [ref]$n)) {
        if ($n -le 0) { return 0 }
        return [Math]::Min($n, $MaxSeconds)
    }
    $d = ConvertTo-DateTime -InputObject $Value -Fallback ([DateTime]::MinValue)
    if ($d -gt [DateTime]::MinValue) {
        $wait = [int](($d - [DateTime]::UtcNow).TotalSeconds)
        return [Math]::Min([Math]::Max(1, $wait), $MaxSeconds)
    }
    return 0
}

function Invoke-FeedFetchWithRetry {
    <#
    .SYNOPSIS
        Fetches a feed with bounded retries, UA rotation on bot-blocks,
        rate-limit handling, conditional requests and per-host pacing.
    .DESCRIPTION
        Request budget: MaxRetries attempts (+2 after a 429), plus at most
        (UserAgents.Count - 1) user-agent rotations, which are only tried on
        403/406. DNS, TLS and oversize failures are not retried. The shared
        HostGate (ConcurrentDictionary[string,long]) is claimed atomically
        before every request so all workers respect the per-host interval.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [string[]]$UserAgents = @('ThreatRaven/5.0'),

        [int]$TimeoutSeconds = 25,

        [int]$MaxRetries = 3,

        [int]$RetryBaseSeconds = 2,

        [hashtable]$FeedCache = $null,

        [bool]$UseConditionalRequests = $true,

        $HostGate = $null,

        [string]$HostGateKey = '',

        [int]$HostIntervalMs = 0,

        [long]$MaxBytes = 10485760,

        [bool]$SkipCertificateValidation = $false,

        [scriptblock]$SleepAction = { param([int]$Ms) Start-Sleep -Milliseconds $Ms }
    )

    $out = [PSCustomObject]@{
        Success    = $false
        Unchanged  = $false
        StatusCode = 0
        Error      = ''
        ErrorKind  = ''
        Bytes      = $null
        Headers    = $null
        Attempts   = 0
        Requests   = 0
        FinalUrl   = $Url
    }

    if ($null -eq $UserAgents -or $UserAgents.Count -eq 0) { $UserAgents = @('ThreatRaven/5.0') }
    $feedHost = ''
    try { $u = [System.Uri]$Url; $feedHost = $u.Scheme + '://' + $u.Host } catch { }

    $uaIndex = 0
    $rotations = 0
    $attempt = 0
    $maxAttempts = [Math]::Max(1, $MaxRetries)
    $extended = $false

    while ($attempt -lt $maxAttempts) {
        $attempt++
        $out.Attempts = $attempt

        $headers = @{
            'User-Agent'      = $UserAgents[$uaIndex]
            'Accept'          = 'application/rss+xml, application/atom+xml, application/rdf+xml;q=0.9, application/xml;q=0.8, text/xml;q=0.8, */*;q=0.1'
            'Accept-Language' = 'en-US,en;q=0.9'
        }
        if ($feedHost) { $headers['Referer'] = $feedHost }
        if ($UseConditionalRequests -and $null -ne $FeedCache) {
            if ($FeedCache['Etag']) { $headers['If-None-Match'] = [string]$FeedCache['Etag'] }
            if ($FeedCache['LastModified']) {
                $lm = ConvertTo-DateTime -InputObject ([string]$FeedCache['LastModified']) -Fallback ([DateTime]::MinValue)
                if ($lm -gt [DateTime]::MinValue) { $headers['If-Modified-Since'] = $lm.ToString('r') }
            }
        }

        # Per-host gate: claim the next slot atomically (retries included)
        if ($HostIntervalMs -gt 0 -and $null -ne $HostGate -and $HostGateKey) {
            $intervalTicks = [long]$HostIntervalMs * 10000
            while ($true) {
                $nowTicks = [DateTime]::UtcNow.Ticks
                $nextAllowed = $HostGate.GetOrAdd($HostGateKey, [long]0)
                if ($nowTicks -ge $nextAllowed) {
                    if ($HostGate.TryUpdate($HostGateKey, $nowTicks + $intervalTicks, $nextAllowed)) { break }
                }
                else {
                    $waitMs = [int][Math]::Min(1000, (($nextAllowed - $nowTicks) / 10000) + 10)
                    & $SleepAction ([Math]::Max(10, $waitMs))
                }
            }
        }

        $r = Invoke-FeedRequest -Url $Url -Headers $headers -TimeoutSeconds $TimeoutSeconds -MaxBytes $MaxBytes -SkipCertificateValidation $SkipCertificateValidation
        $out.Requests++
        $out.StatusCode = $r.StatusCode
        $out.ErrorKind = $r.ErrorKind
        $out.FinalUrl = $r.FinalUrl
        if ($r.Error) { $out.Error = $r.Error }

        $action = Get-HttpStatusAction -StatusCode $r.StatusCode -ErrorKind $r.ErrorKind
        switch ($action) {
            'success' {
                $out.Success = $true
                $out.Bytes = $r.Bytes
                $out.Headers = $r.Headers
                $out.Error = ''
                return $out
            }
            'unchanged' {
                $out.Success = $true
                $out.Unchanged = $true
                $out.Headers = $r.Headers
                $out.Error = ''
                return $out
            }
            'permanent' {
                if (-not $out.Error) { $out.Error = "HTTP $($r.StatusCode)" }
                return $out
            }
            'rotate-ua' {
                if ($rotations -lt ($UserAgents.Count - 1)) {
                    $rotations++
                    $uaIndex++
                    $attempt--          # a UA rotation does not consume a retry
                    & $SleepAction 500
                    continue
                }
                $out.Error = "HTTP $($r.StatusCode) (blocked for all $($UserAgents.Count) user agents)"
                return $out
            }
            'ratelimit' {
                if (-not $extended) { $maxAttempts += 2; $extended = $true }
                $out.Error = 'HTTP 429 (rate limited)'
                if ($attempt -lt $maxAttempts) {
                    $delay = Get-RetryAfterSeconds -Value (Get-WebResponseHeader -Response $r.Headers -Name 'Retry-After')
                    if ($delay -le 0) { $delay = 5 }
                    & $SleepAction ($delay * 1000)
                }
                continue
            }
            default {
                if (-not $out.Error) { $out.Error = "HTTP $($r.StatusCode)" }
                if ($attempt -lt $maxAttempts) {
                    $delay = $RetryBaseSeconds * [Math]::Pow(2, $attempt - 1)
                    $jitter = Get-Random -Minimum 0 -Maximum ([Math]::Max(1, [int]($delay / 2)))
                    & $SleepAction ([int](($delay + $jitter) * 1000))
                }
            }
        }
    }

    if (-not $out.Error) { $out.Error = 'Fetch failed' }
    return $out
}

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------
function Merge-ConfigDefaults {
    <#
    .SYNOPSIS
        Deep-merges default settings into a parsed config object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config
    )

    $defaults = @{
        VulnDays                  = 7
        ThrottleLimit             = 10
        FeedTimeoutSeconds        = 30
        MaxRetries                = 3
        RetryBaseDelaySeconds     = 2
        MaxResponseBytes          = 20971520
        LogLevel                  = 'Info'
        ValidateCertificates      = $true
        ExportHealthReport        = $false
        NvdEnabled                = $true
        NvdApiKey                 = ''
        NvdMaxResults             = 2000
        NvdCacheHours             = 6
        NvdKeywordFilter          = $false
        KevEnabled                = $true
        EpssEnabled               = $true
        EnrichmentCacheHours      = 12
        MitreMinKeywordHits       = 1
        MinHostRequestIntervalMs  = 250
        HostRequestIntervalMsOverrides = [PSCustomObject]@{}
        GlobalTimeoutSeconds      = 900
        StateRetentionDays        = 90
        StateMaxEntries           = 20000
        ReportHistoryDays         = 7
        LogRetentionDays          = 14
        EnableConditionalRequests = $true
        WebhookEnabled            = $false
        WebhookUrl                = ''
    }

    if (-not $Config.PSObject.Properties['Settings'] -or $null -eq $Config.Settings) {
        $Config | Add-Member -NotePropertyName Settings -NotePropertyValue ([PSCustomObject]@{}) -Force
    }

    foreach ($key in $defaults.Keys) {
        $existing = $Config.Settings.PSObject.Properties[$key]
        if ($null -eq $existing -or $null -eq $existing.Value) {
            $Config.Settings | Add-Member -NotePropertyName $key -NotePropertyValue $defaults[$key] -Force
        }
    }

    if (-not $Config.PSObject.Properties['SchemaVersion']) {
        $Config | Add-Member -NotePropertyName SchemaVersion -NotePropertyValue 2 -Force
    }

    return $Config
}

function ConvertTo-FeedDefinition {
    <#
    .SYNOPSIS
        Normalizes a feed entry (string URL or {Url, Name, Category} object)
        into a PSCustomObject with Url, Name and Category.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Feed
    )

    if ($null -eq $Feed) { return $null }

    $url = ''
    $name = ''
    $category = ''
    if ($Feed -is [string]) {
        $url = $Feed
    }
    else {
        $u = Get-ObjectProperty -Item $Feed -Name 'Url'
        if ($null -eq $u) { $u = Get-ObjectProperty -Item $Feed -Name 'url' }
        $url = [string]$u
        $n = Get-ObjectProperty -Item $Feed -Name 'Name'
        if ($null -eq $n) { $n = Get-ObjectProperty -Item $Feed -Name 'name' }
        if ($null -ne $n) { $name = [string]$n }
        $c = Get-ObjectProperty -Item $Feed -Name 'Category'
        if ($null -eq $c) { $c = Get-ObjectProperty -Item $Feed -Name 'category' }
        if ($null -ne $c) { $category = [string]$c }
    }

    $url = $url.Trim()
    if ([string]::IsNullOrWhiteSpace($url)) { return $null }

    if ([string]::IsNullOrWhiteSpace($name)) {
        try {
            $name = ([System.Uri]$url).Host
            if ($name -match '^www\.') { $name = $name.Substring(4) }
        }
        catch { $name = $url }
    }
    if ([string]::IsNullOrWhiteSpace($category)) { $category = 'General' }

    return [PSCustomObject]@{
        Url      = $url
        Name     = $name.Trim()
        Category = $category.Trim()
    }
}

function Get-FeedDefinitions {
    <#
    .SYNOPSIS
        Returns the configured feeds as normalized definitions, de-duplicated by URL.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config
    )

    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $defs = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($f in @($Config.Feeds)) {
        $d = ConvertTo-FeedDefinition -Feed $f
        if ($null -eq $d) { continue }
        if (-not $seen.Add($d.Url)) {
            Write-Warning "Duplicate feed ignored: $($d.Url)"
            continue
        }
        $defs.Add($d)
    }
    return $defs.ToArray()
}

function Test-Configuration {
    <#
    .SYNOPSIS
        Validates the configuration file has all required fields and sane values.
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

    if (@($Config.Keywords).Count -eq 0) {
        throw "Configuration Keywords array is empty"
    }

    if (@($Config.Feeds).Count -eq 0) {
        throw "Configuration Feeds array is empty"
    }

    if (@($Config.UserAgents).Count -eq 0) {
        throw "Configuration UserAgents array is empty"
    }

    if (-not $Config.PSObject.Properties['AllowedUrlPatterns'] -or @($Config.AllowedUrlPatterns).Count -eq 0) {
        throw "Configuration AllowedUrlPatterns is missing or empty"
    }

    foreach ($feed in $Config.Feeds) {
        $d = ConvertTo-FeedDefinition -Feed $feed
        if ($null -eq $d) {
            throw "Configuration Feeds contains an entry without a URL"
        }
        if ($d.Url -notmatch '^https?://') {
            throw "Configuration Feeds entry is not an http(s) URL: $($d.Url)"
        }
    }

    foreach ($tid in $Config.MitreKeywords.PSObject.Properties.Name) {
        $entry = $Config.MitreKeywords.$tid
        if ($tid -notmatch '^T\d{4}(\.\d{3})?$') {
            throw "MITRE entry '$tid' is not a valid technique ID"
        }
        if (-not $entry.PSObject.Properties['Name'] -or [string]::IsNullOrWhiteSpace([string]$entry.Name)) {
            throw "MITRE entry '$tid' is missing Name"
        }
        $validKeywords = @()
        if ($entry.PSObject.Properties['Keywords']) {
            foreach ($k in $entry.Keywords) {
                if ($null -ne $k -and -not [string]::IsNullOrWhiteSpace([string]$k)) {
                    $validKeywords += $k
                }
            }
        }
        if ($validKeywords.Count -eq 0) {
            throw "MITRE entry '$tid' is missing Keywords"
        }
    }

    $s = $Config.Settings
    if ($s.ThrottleLimit -lt 1 -or $s.ThrottleLimit -gt 64) { throw "ThrottleLimit must be between 1 and 64" }
    if ($s.MaxRetries -lt 1)          { throw "MaxRetries must be greater than 0" }
    if ($s.FeedTimeoutSeconds -lt 1)  { throw "FeedTimeoutSeconds must be greater than 0" }
    if ($s.RetryBaseDelaySeconds -lt 0) { throw "RetryBaseDelaySeconds must be >= 0" }
    if ($s.MaxResponseBytes -lt 65536) { throw "MaxResponseBytes must be >= 65536" }
    if ($s.VulnDays -lt 1 -or $s.VulnDays -gt 120) { throw "VulnDays must be between 1 and 120 (NVD window limit)" }
    if ($s.GlobalTimeoutSeconds -lt 60) { throw "GlobalTimeoutSeconds must be >= 60" }
    if ($s.NvdMaxResults -lt 1)       { throw "NvdMaxResults must be greater than 0" }
    if ($s.ReportHistoryDays -lt 0)   { throw "ReportHistoryDays must be >= 0" }
    if ($s.StateRetentionDays -lt 1)  { throw "StateRetentionDays must be greater than 0" }
    if ($s.MitreMinKeywordHits -lt 1) { throw "MitreMinKeywordHits must be >= 1" }
    if ($s.MinHostRequestIntervalMs -lt 0) { throw "MinHostRequestIntervalMs must be >= 0" }
    if ($s.LogLevel -notin @('Debug', 'Info', 'Warning', 'Error')) {
        throw "LogLevel must be one of: Debug, Info, Warning, Error"
    }
    if ([bool]$s.WebhookEnabled -and -not [string]::IsNullOrWhiteSpace([string]$s.WebhookUrl) -and ([string]$s.WebhookUrl) -notmatch '^https://') {
        throw "WebhookUrl must use https://"
    }

    if ($s.PSObject.Properties['HostRequestIntervalMsOverrides'] -and $null -ne $s.HostRequestIntervalMsOverrides) {
        foreach ($ov in $s.HostRequestIntervalMsOverrides.PSObject.Properties) {
            $ovInt = 0
            if (-not [int]::TryParse([string]$ov.Value, [ref]$ovInt) -or $ovInt -lt 0) {
                throw "HostRequestIntervalMsOverrides['$($ov.Name)'] must be a non-negative integer (milliseconds)"
            }
        }
    }

    if ($Config.PSObject.Properties['SchemaVersion'] -and $Config.SchemaVersion -gt 2) {
        Write-Warning "Config SchemaVersion $($Config.SchemaVersion) is newer than supported (2); some settings may be ignored"
    }

    Write-Verbose "Configuration validation passed"
    return $true
}

function Initialize-Configuration {
    <#
    .SYNOPSIS
        Loads, merges defaults into, applies environment overrides, and validates the configuration file.
    .DESCRIPTION
        THREATRAVEN_NVD_API_KEY and THREATRAVEN_WEBHOOK_URL override the
        corresponding settings so secrets need not live in config.json.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Configuration file not found at: $Path"
    }

    try {
        $config = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        $null = Merge-ConfigDefaults -Config $config

        $envKey = [Environment]::GetEnvironmentVariable('THREATRAVEN_NVD_API_KEY')
        if (-not [string]::IsNullOrWhiteSpace($envKey)) {
            $config.Settings | Add-Member -NotePropertyName NvdApiKey -NotePropertyValue $envKey.Trim() -Force
        }
        $envHook = [Environment]::GetEnvironmentVariable('THREATRAVEN_WEBHOOK_URL')
        if (-not [string]::IsNullOrWhiteSpace($envHook)) {
            $config.Settings | Add-Member -NotePropertyName WebhookUrl -NotePropertyValue $envHook.Trim() -Force
        }

        $null = Test-Configuration -Config $config
        return $config
    }
    catch {
        throw "Failed to parse configuration: $($_.Exception.Message)"
    }
}

# ------------------------------------------------------------
# Feed health
# ------------------------------------------------------------
function Get-FeedStatusLabel {
    <#
    .SYNOPSIS
        Classifies a feed's health.
    .DESCRIPTION
        With run history (RecentRuns > 0, counts include the current run):
          unhealthy = failed this run and >= 2 failures in the recent window
          degraded  = failed this run (first recent failure), or succeeded
                      this run but >= 2 recent failures
          healthy   = otherwise
        Without history the v4 rules apply (unhealthy = failed and never
        succeeded; degraded = more than 2 failures).
    #>
    [CmdletBinding()]
    param(
        [int]$SuccessCount = 0,

        [int]$FailureCount = 0,

        [int]$RecentRuns = 0,

        [int]$RecentFailures = 0
    )

    $failedNow = ($FailureCount -gt 0 -and $SuccessCount -eq 0)

    if ($RecentRuns -gt 0) {
        if ($failedNow) {
            if ($RecentFailures -ge 2) { return 'unhealthy' }
            return 'degraded'
        }
        if ($RecentFailures -ge 2) { return 'degraded' }
        return 'healthy'
    }

    if ($failedNow) { return 'unhealthy' }
    if ($FailureCount -gt 2) { return 'degraded' }
    return 'healthy'
}

function Get-FeedHealthReport {
    <#
    .SYNOPSIS
        Generates a health report for monitored feeds.
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
        $health = $entry.Value

        $totalSuccess += $health.SuccessCount
        $totalFailures += $health.FailureCount

        $recentRuns = 0
        $recentFailures = 0
        if ($health.PSObject.Properties['RecentRuns']) { $recentRuns = [int]$health.RecentRuns }
        if ($health.PSObject.Properties['RecentFailures']) { $recentFailures = [int]$health.RecentFailures }

        $label = Get-FeedStatusLabel -SuccessCount $health.SuccessCount -FailureCount $health.FailureCount `
            -RecentRuns $recentRuns -RecentFailures $recentFailures
        if ($label -eq 'healthy') {
            $healthy++
        }
        else {
            if ($label -eq 'unhealthy') { $unhealthy++ } else { $degraded++ }
            $name = if ($health.PSObject.Properties['Name']) { $health.Name } else { $health.Host }
            $unhealthyList.Add([PSCustomObject]@{
                Feed        = $entry.Key
                Name        = $name
                Host        = $health.Host
                Status      = $label.ToUpperInvariant()
                Failures    = $health.FailureCount
                RecentFailures = $recentFailures
                LastError   = $health.LastError
                LastChecked = $health.LastChecked
            })
        }
    }

    return [PSCustomObject]@{
        Healthy       = $healthy
        Degraded      = $degraded
        Unhealthy     = $unhealthy
        TotalSuccess  = $totalSuccess
        TotalFailures = $totalFailures
        UnhealthyFeeds = $unhealthyList
        Timestamp     = Get-Date
    }
}

function Export-FeedHealthReport {
    <#
    .SYNOPSIS
        Exports feed health data to a JSON file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Concurrent.ConcurrentDictionary[string,PSObject]]$FeedHealth,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $report = Get-FeedHealthReport -FeedHealth $FeedHealth

    $feeds = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($entry in $FeedHealth.GetEnumerator()) {
        $v = $entry.Value
        $avgMs = 0.0
        if ($v.ResponseTimes -is [System.Collections.Generic.List[double]] -and $v.ResponseTimes.Count -gt 0) {
            $sum = 0.0
            foreach ($t in $v.ResponseTimes) { $sum += $t }
            $avgMs = [math]::Round($sum / $v.ResponseTimes.Count, 1)
        }
        $recentRuns = 0; $recentFailures = 0; $name = $v.Host; $category = ''
        if ($v.PSObject.Properties['RecentRuns']) { $recentRuns = $v.RecentRuns }
        if ($v.PSObject.Properties['RecentFailures']) { $recentFailures = $v.RecentFailures }
        if ($v.PSObject.Properties['Name']) { $name = $v.Name }
        if ($v.PSObject.Properties['Category']) { $category = $v.Category }
        $feeds.Add([PSCustomObject]@{
            FeedUrl        = $entry.Key
            Name           = $name
            Category       = $category
            Host           = $v.Host
            Status         = Get-FeedStatusLabel -SuccessCount $v.SuccessCount -FailureCount $v.FailureCount -RecentRuns $recentRuns -RecentFailures $recentFailures
            SuccessCount   = $v.SuccessCount
            FailureCount   = $v.FailureCount
            RecentRuns     = $recentRuns
            RecentFailures = $recentFailures
            TotalItems     = $v.TotalItems
            TotalMatches   = $v.TotalMatches
            AvgResponseMs  = $avgMs
            LastError      = $v.LastError
            LastChecked    = $v.LastChecked
        })
    }

    $exportData = [PSCustomObject]@{
        GeneratedAt = $report.Timestamp
        Summary = [PSCustomObject]@{
            Healthy       = $report.Healthy
            Degraded      = $report.Degraded
            Unhealthy     = $report.Unhealthy
            TotalSuccess  = $report.TotalSuccess
            TotalFailures = $report.TotalFailures
        }
        Feeds = $feeds.ToArray()
    }

    $exportData | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $Path -Encoding UTF8
    Write-Verbose "Feed health report exported to: $Path"
}

function Save-RunConfiguration {
    <#
    .SYNOPSIS
        Saves the current run configuration for audit purposes (secrets redacted).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config,

        [Parameter(Mandatory)]
        [string]$Path,

        [string]$StatePath = ''
    )

    $secretKeys = @('NvdApiKey', 'WebhookUrl')
    $settingsCopy = [ordered]@{}
    foreach ($p in $Config.Settings.PSObject.Properties) {
        if ($p.Name -in $secretKeys -and -not [string]::IsNullOrEmpty([string]$p.Value)) {
            $settingsCopy[$p.Name] = '***REDACTED***'
        }
        else {
            $settingsCopy[$p.Name] = $p.Value
        }
    }

    $runConfig = [PSCustomObject]@{
        Timestamp           = Get-Date
        SchemaVersion       = $Config.SchemaVersion
        Settings            = [PSCustomObject]$settingsCopy
        FeedCount           = @($Config.Feeds).Count
        KeywordCount        = @($Config.Keywords).Count
        MitreTechniqueCount = @($Config.MitreKeywords.PSObject.Properties.Name).Count
        StateFile           = $StatePath
    }

    $runConfig | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $Path -Encoding UTF8
}

# ------------------------------------------------------------
# Persistent state
# ------------------------------------------------------------
function Read-ThreatRavenStateFile {
    <#
    .SYNOPSIS
        Parses a state JSON file into the in-memory state shape. Throws on corruption.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        $State
    )

    $loaded = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($null -eq $loaded) { throw 'State file is empty' }

    if ($loaded.PSObject.Properties['Items'] -and $null -ne $loaded.Items) {
        $items = @{}
        foreach ($p in $loaded.Items.PSObject.Properties) { $items[$p.Name] = $p.Value }
        $State.Items = $items
    }

    if ($loaded.PSObject.Properties['FeedCache'] -and $null -ne $loaded.FeedCache) {
        $cache = @{}
        foreach ($p in $loaded.FeedCache.PSObject.Properties) { $cache[$p.Name] = $p.Value }
        $State.FeedCache = $cache
    }

    if ($loaded.PSObject.Properties['FeedHistory'] -and $null -ne $loaded.FeedHistory) {
        $hist = @{}
        foreach ($p in $loaded.FeedHistory.PSObject.Properties) { $hist[$p.Name] = @($p.Value) }
        $State.FeedHistory = $hist
    }

    if ($loaded.PSObject.Properties['NvdCache'] -and $null -ne $loaded.NvdCache) {
        $State.NvdCache = $loaded.NvdCache
    }
    if ($loaded.PSObject.Properties['KevCache'] -and $null -ne $loaded.KevCache) {
        $State.KevCache = $loaded.KevCache
    }
    if ($loaded.PSObject.Properties['EpssCache'] -and $null -ne $loaded.EpssCache) {
        $State.EpssCache = $loaded.EpssCache
    }

    if ($loaded.PSObject.Properties['HealthHistory'] -and $null -ne $loaded.HealthHistory) {
        $State.HealthHistory = @($loaded.HealthHistory)
    }
}

function Initialize-ThreatRavenState {
    <#
    .SYNOPSIS
        Loads (or creates) the persistent state file.
    .DESCRIPTION
        If the state file is corrupt it is preserved as <path>.corrupt-<ts>
        (never over the .bak, which holds the last good save) and the .bak
        is loaded instead when possible.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $state = [PSCustomObject]@{
        SchemaVersion  = 2
        Items          = @{}
        FeedCache      = @{}
        FeedHistory    = @{}
        NvdCache       = $null
        KevCache       = $null
        EpssCache      = $null
        HealthHistory  = @()
        UpdatedAt      = (Get-Date).ToString('o')
    }

    if (-not (Test-Path -LiteralPath $Path)) { return $state }

    try {
        Read-ThreatRavenStateFile -Path $Path -State $state
        return $state
    }
    catch {
        $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $corrupt = "$Path.corrupt-$stamp"
        Copy-Item -LiteralPath $Path -Destination $corrupt -Force -ErrorAction SilentlyContinue
        Write-Warning "State file was corrupt and has been preserved as ${corrupt}: $($_.Exception.Message)"
    }

    $bak = "$Path.bak"
    if (Test-Path -LiteralPath $bak) {
        try {
            Read-ThreatRavenStateFile -Path $bak -State $state
            Write-Warning "Recovered state from backup: $bak"
        }
        catch {
            Write-Warning "Backup state file is also unreadable ($bak); starting with empty state"
        }
    }
    return $state
}

function Save-ThreatRavenState {
    <#
    .SYNOPSIS
        Prunes and persists the state file atomically (temp + swap, .bak kept).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $State,

        [Parameter(Mandatory)]
        [string]$Path,

        [int]$RetentionDays = 90,

        [int]$MaxEntries = 20000
    )

    $now = [DateTime]::UtcNow
    $cutoff = $now.AddDays(-$RetentionDays)
    $items = $State.Items

    if ($items -is [hashtable]) {
        # Parse each LastSeen once
        $lastSeen = @{}
        foreach ($key in @($items.Keys)) {
            $ls = $null
            $v = $items[$key]
            if ($null -ne $v -and $v.PSObject.Properties['LastSeen']) { $ls = [string]$v.LastSeen }
            $lastSeen[$key] = ConvertTo-DateTime -InputObject ([string]$ls) -Fallback $now
            if ($lastSeen[$key] -lt $cutoff) {
                $items.Remove($key)
                $lastSeen.Remove($key)
            }
        }

        if ($items.Count -gt $MaxEntries) {
            $sorted = @($lastSeen.GetEnumerator() | Sort-Object -Property Value -Descending)
            for ($i = $MaxEntries; $i -lt $sorted.Count; $i++) {
                $items.Remove($sorted[$i].Key)
            }
        }
    }

    if ($State.PSObject.Properties['FeedHistory'] -and $State.FeedHistory -is [hashtable]) {
        foreach ($k in @($State.FeedHistory.Keys)) {
            $runs = @($State.FeedHistory[$k])
            if ($runs.Count -gt 10) { $State.FeedHistory[$k] = @($runs | Select-Object -Last 10) }
        }
    }

    if (@($State.HealthHistory).Count -gt 90) {
        $State.HealthHistory = @($State.HealthHistory | Select-Object -Last 90)
    }

    $State.UpdatedAt = $now.ToString('o')

    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        $Path = Join-Path (Get-Location).Path $Path
    }

    $dir = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $json = $State | ConvertTo-Json -Depth 10 -Compress
    $tmpPath = "$Path.tmp"
    [System.IO.File]::WriteAllText($tmpPath, $json, [System.Text.UTF8Encoding]::new($false))

    if (Test-Path -LiteralPath $Path) {
        try {
            [System.IO.File]::Replace($tmpPath, $Path, "$Path.bak")
        }
        catch {
            Move-Item -LiteralPath $tmpPath -Destination $Path -Force
        }
    }
    else {
        Move-Item -LiteralPath $tmpPath -Destination $Path -Force
    }
}

function Update-FeedRunHistory {
    <#
    .SYNOPSIS
        Appends this run's outcome for a feed to State.FeedHistory and returns
        the recent window (RecentRuns / RecentFailures, current run included).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $State,

        [Parameter(Mandatory)]
        [string]$FeedUrl,

        [Parameter(Mandatory)]
        [bool]$Success,

        [int]$Window = 5
    )

    if (-not $State.PSObject.Properties['FeedHistory'] -or $State.FeedHistory -isnot [hashtable]) {
        $State | Add-Member -NotePropertyName FeedHistory -NotePropertyValue @{} -Force
    }
    $runs = [System.Collections.Generic.List[PSObject]]::new()
    if ($State.FeedHistory.ContainsKey($FeedUrl)) {
        foreach ($r in @($State.FeedHistory[$FeedUrl])) { if ($null -ne $r) { $runs.Add($r) } }
    }
    $runs.Add([PSCustomObject]@{ Ts = [DateTime]::UtcNow.ToString('o'); Ok = $Success })
    while ($runs.Count -gt 10) { $runs.RemoveAt(0) }
    $State.FeedHistory[$FeedUrl] = $runs.ToArray()

    $recent = @($runs | Select-Object -Last $Window)
    $fails = 0
    foreach ($r in $recent) {
        $ok = $true
        if ($r.PSObject.Properties['Ok']) { $ok = [bool]$r.Ok }
        if (-not $ok) { $fails++ }
    }
    return [PSCustomObject]@{ RecentRuns = $recent.Count; RecentFailures = $fails }
}

function Get-ThreatRavenHistoryItems {
    <#
    .SYNOPSIS
        Returns previously-seen items whose publication date falls within
        the last N days, for inclusion in reports as "seen" entries.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $State,

        [int]$Days = 7
    )

    $cutoff = [DateTime]::UtcNow.AddDays(-$Days)
    $items = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($entry in $State.Items.GetEnumerator()) {
        $item = $entry.Value
        $dateStr = ''
        if ($item.PSObject.Properties['Date']) { $dateStr = [string]$item.Date }
        $d = ConvertTo-DateTime -InputObject $dateStr -Fallback ([DateTime]::MinValue)
        if ($d -ge $cutoff) {
            $items.Add($item)
        }
    }

    return $items.ToArray()
}

# ------------------------------------------------------------
# CVE enrichment: NVD, CISA KEV, FIRST EPSS
# ------------------------------------------------------------
function Get-NvdCves {
    <#
    .SYNOPSIS
        Fetches CVEs published in the last N days from the NVD API.
    .DESCRIPTION
        Runs server-side with pagination, respects NVD rate limits
        (5 requests/30s without an API key, 50/30s with one), supports
        optional keyword correlation filtering, handles CVSS 4.0/3.1/3.0/2.0,
        and caches results in the state file.
    #>
    [CmdletBinding()]
    param(
        [int]$Days = 7,

        [string]$ApiKey = '',

        [int]$MaxResults = 2000,

        [string[]]$Keywords = @(),

        [bool]$KeywordFilter = $false,

        [AllowNull()]
        $State = $null,

        [int]$CacheHours = 6
    )

    if ($null -ne $State -and $null -ne $State.NvdCache) {
        $cached = $State.NvdCache
        $sameShape = $cached.PSObject.Properties['Days'] -and $cached.Days -eq $Days -and
            $cached.PSObject.Properties['FetchedAt'] -and
            $cached.PSObject.Properties['SchemaVersion'] -and ([int]$cached.SchemaVersion) -eq 2 -and
            $cached.PSObject.Properties['KeywordFilter'] -and ([bool]$cached.KeywordFilter) -eq $KeywordFilter -and
            $cached.PSObject.Properties['MaxResults'] -and ([int]$cached.MaxResults) -eq $MaxResults
        if ($sameShape) {
            $age = ([DateTime]::UtcNow - (ConvertTo-DateTime -InputObject ([string]$cached.FetchedAt) -Fallback ([DateTime]::MinValue))).TotalHours
            if ($age -ge 0 -and $age -lt $CacheHours) {
                Write-Verbose "Using cached NVD data ($([math]::Round($age, 1)) hours old)"
                return $cached
            }
        }
    }

    $end = [DateTime]::UtcNow
    $start = $end.AddDays(-$Days)
    $startStr = $start.ToString('yyyy-MM-ddTHH:mm:ss.fff') + 'Z'
    $endStr = $end.ToString('yyyy-MM-ddTHH:mm:ss.fff') + 'Z'

    $all = [System.Collections.Generic.List[PSObject]]::new()
    $startIndex = 0
    $totalResults = 0
    $truncated = $false
    $pageSize = 2000

    do {
        $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=$startStr&pubEndDate=$endStr&startIndex=$startIndex&resultsPerPage=$pageSize"
        $headers = @{
            'User-Agent' = 'ThreatRaven/5.0 (APT Intelligence Feed Monitor)'
        }
        if ($ApiKey) { $headers['apiKey'] = $ApiKey }

        $ok = $false
        $attempt = 0
        $resp = $null
        while (-not $ok -and $attempt -lt 3) {
            $attempt++
            try {
                $resp = Invoke-RestMethod -Uri $url -Headers $headers -TimeoutSec 90
                $ok = $true
            }
            catch {
                $status = 0
                if ($null -ne $_.Exception.Response -and $null -ne $_.Exception.Response.StatusCode) {
                    $status = [int]$_.Exception.Response.StatusCode
                }
                if ($status -eq 429 -or $status -eq 403 -or $status -eq 503) {
                    Start-Sleep -Seconds $(if ($ApiKey) { 2 } else { 8 })
                }
                elseif ($status -ge 400) {
                    throw "NVD API error: HTTP $status - $($_.Exception.Message)"
                }
                else {
                    Start-Sleep -Seconds 3
                }
            }
        }

        if (-not $ok) {
            throw 'NVD API request failed after retries'
        }
        if ($null -eq $resp -or $null -eq (Get-ObjectProperty -Item $resp -Name 'totalResults')) {
            throw 'Unexpected NVD API response (missing totalResults)'
        }

        $totalResults = [int]$resp.totalResults
        foreach ($v in @($resp.vulnerabilities)) {
            $all.Add($v)
        }
        $startIndex += [int]$resp.resultsPerPage

        if ($all.Count -ge $MaxResults) {
            $truncated = $true
            break
        }

        if ($startIndex -lt $totalResults) {
            if ($ApiKey) { Start-Sleep -Milliseconds 700 }
            else { Start-Sleep -Seconds 6 }
        }
    } while ($startIndex -lt $totalResults)

    $keywordRx = @()
    foreach ($kw in $Keywords) {
        if (-not [string]::IsNullOrWhiteSpace($kw)) {
            $keywordRx += [regex]::new('\b' + [regex]::Escape($kw) + '\b', $script:RxCI, $script:RegexTimeout)
        }
    }

    $mapped = [System.Collections.Generic.List[PSObject]]::new()
    $mappedCount = 0
    foreach ($v in $all) {
        if ($mappedCount -ge $MaxResults) { break }
        $mappedCount++

        $cve = $v.cve
        $metrics = Get-ObjectProperty -Item $cve -Name 'metrics'

        $severity = 'UNKNOWN'
        $score = 0.0
        $cvssVersion = ''

        if ($null -ne $metrics) {
            foreach ($mv in @(@{ Key = 'cvssMetricV40'; V = '4.0' }, @{ Key = 'cvssMetricV31'; V = '3.1' }, @{ Key = 'cvssMetricV30'; V = '3.0' }, @{ Key = 'cvssMetricV3'; V = '3.0' }, @{ Key = 'cvssMetricV2'; V = '2.0' })) {
                $m = Get-ObjectProperty -Item $metrics -Name $mv.Key
                if ($null -eq $m -or @($m).Count -eq 0) { continue }
                $first = @($m)[0]
                $data = Get-ObjectProperty -Item $first -Name 'cvssData'
                if ($null -eq $data) { continue }
                $sev = Get-ObjectProperty -Item $data -Name 'baseSeverity'
                if ($null -eq $sev) { $sev = Get-ObjectProperty -Item $first -Name 'baseSeverity' }
                $sc = Get-ObjectProperty -Item $data -Name 'baseScore'
                if ($null -ne $sc) {
                    $score = [double]$sc
                    if ($null -ne $sev) { $severity = ([string]$sev).ToUpperInvariant() }
                    elseif ($score -ge 9) { $severity = 'CRITICAL' } elseif ($score -ge 7) { $severity = 'HIGH' } elseif ($score -ge 4) { $severity = 'MEDIUM' } elseif ($score -gt 0) { $severity = 'LOW' }
                    $cvssVersion = $mv.V
                    break
                }
            }
        }

        $desc = ''
        $descriptions = Get-ObjectProperty -Item $cve -Name 'descriptions'
        if ($null -ne $descriptions) {
            foreach ($d in $descriptions) {
                if ($d.PSObject.Properties['lang'] -and [string]$d.lang -eq 'en') {
                    $desc = [string]$d.value
                    break
                }
            }
        }

        if ($KeywordFilter -and $keywordRx.Count -gt 0) {
            $matched = $false
            foreach ($rx in $keywordRx) {
                try { if ($rx.IsMatch($desc)) { $matched = $true; break } } catch { }
            }
            if (-not $matched) { continue }
        }

        $mapped.Add([PSCustomObject]@{
            id          = [string]$cve.id
            published   = [string]$cve.published
            severity    = $severity
            score       = $score
            cvss        = $cvssVersion
            description = $desc
        })
    }

    $result = [PSCustomObject]@{
        SchemaVersion = 2
        FetchedAt     = [DateTime]::UtcNow.ToString('o')
        Days          = $Days
        KeywordFilter = $KeywordFilter
        MaxResults    = $MaxResults
        Truncated     = $truncated
        Cves          = $mapped.ToArray()
    }

    if ($null -ne $State) {
        $State.NvdCache = $result
    }

    return $result
}

function Get-CisaKev {
    <#
    .SYNOPSIS
        Downloads the CISA Known Exploited Vulnerabilities catalog (cached in state).
    .OUTPUTS
        Hashtable: CVE-ID -> @{ DateAdded; Ransomware; Vendor; Product }
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        $State = $null,

        [int]$CacheHours = 12,

        [string]$Url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',

        [int]$TimeoutSeconds = 60
    )

    $table = @{}

    if ($null -ne $State -and $null -ne $State.KevCache -and $State.KevCache.PSObject.Properties['FetchedAt']) {
        $age = ([DateTime]::UtcNow - (ConvertTo-DateTime -InputObject ([string]$State.KevCache.FetchedAt) -Fallback ([DateTime]::MinValue))).TotalHours
        if ($age -ge 0 -and $age -lt $CacheHours -and $State.KevCache.PSObject.Properties['Items']) {
            foreach ($p in $State.KevCache.Items.PSObject.Properties) { $table[$p.Name] = $p.Value }
            Write-Verbose "Using cached KEV catalog ($($table.Count) entries, $([math]::Round($age, 1)) hours old)"
            return $table
        }
    }

    $r = Invoke-FeedRequest -Url $Url -Headers @{ 'User-Agent' = 'ThreatRaven/5.0 (APT Intelligence Feed Monitor)'; 'Accept' = 'application/json' } `
        -TimeoutSeconds $TimeoutSeconds -MaxBytes 33554432
    if (-not ($r.StatusCode -ge 200 -and $r.StatusCode -lt 300) -or $null -eq $r.Bytes) {
        $err = if ($r.Error) { $r.Error } else { "HTTP $($r.StatusCode)" }
        throw "KEV download failed: $err"
    }

    $json = [System.Text.Encoding]::UTF8.GetString($r.Bytes) | ConvertFrom-Json
    $vulns = Get-ObjectProperty -Item $json -Name 'vulnerabilities'
    if ($null -eq $vulns) { throw 'KEV catalog has no vulnerabilities array' }

    $items = [ordered]@{}
    foreach ($v in $vulns) {
        $id = [string](Get-ObjectProperty -Item $v -Name 'cveID')
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        $id = $id.ToUpperInvariant()
        $ransom = [string](Get-ObjectProperty -Item $v -Name 'knownRansomwareCampaignUse')
        $entry = [PSCustomObject]@{
            DateAdded  = [string](Get-ObjectProperty -Item $v -Name 'dateAdded')
            Ransomware = ($ransom -eq 'Known')
            Vendor     = [string](Get-ObjectProperty -Item $v -Name 'vendorProject')
            Product    = [string](Get-ObjectProperty -Item $v -Name 'product')
        }
        $items[$id] = $entry
        $table[$id] = $entry
    }

    if ($null -ne $State) {
        $State.KevCache = [PSCustomObject]@{
            FetchedAt = [DateTime]::UtcNow.ToString('o')
            Count     = $table.Count
            Items     = [PSCustomObject]$items
        }
    }

    return $table
}

function Get-EpssScores {
    <#
    .SYNOPSIS
        Fetches FIRST EPSS exploit-probability scores for a set of CVE IDs (cached in state).
    .OUTPUTS
        Hashtable: CVE-ID -> @{ Epss (0..1); Percentile (0..1) }
    #>
    [CmdletBinding()]
    param(
        [string[]]$CveIds = @(),

        [AllowNull()]
        $State = $null,

        [int]$CacheHours = 12,

        [int]$MaxRequests = 60,

        [int]$BatchSize = 100
    )

    $table = @{}
    $wanted = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($c in $CveIds) { if (-not [string]::IsNullOrWhiteSpace($c)) { $null = $wanted.Add($c.Trim().ToUpperInvariant()) } }
    if ($wanted.Count -eq 0) { return $table }

    $cacheItems = @{}
    if ($null -ne $State -and $null -ne $State.EpssCache -and $State.EpssCache.PSObject.Properties['Items']) {
        foreach ($p in $State.EpssCache.Items.PSObject.Properties) { $cacheItems[$p.Name] = $p.Value }
    }

    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $wanted) {
        $hit = $null
        if ($cacheItems.ContainsKey($id)) { $hit = $cacheItems[$id] }
        if ($null -ne $hit -and $hit.PSObject.Properties['FetchedAt']) {
            $age = ([DateTime]::UtcNow - (ConvertTo-DateTime -InputObject ([string]$hit.FetchedAt) -Fallback ([DateTime]::MinValue))).TotalHours
            if ($age -ge 0 -and $age -lt $CacheHours) {
                $table[$id] = $hit
                continue
            }
        }
        $missing.Add($id)
    }

    $requests = 0
    $headers = @{ 'User-Agent' = 'ThreatRaven/5.0 (APT Intelligence Feed Monitor)'; 'Accept' = 'application/json' }
    for ($i = 0; $i -lt $missing.Count -and $requests -lt $MaxRequests; $i += $BatchSize) {
        $batch = $missing.GetRange($i, [Math]::Min($BatchSize, $missing.Count - $i))
        $url = 'https://api.first.org/data/v1/epss?cve=' + ($batch -join ',')
        $requests++
        $r = Invoke-FeedRequest -Url $url -Headers $headers -TimeoutSeconds 45 -MaxBytes 8388608
        if (-not ($r.StatusCode -ge 200 -and $r.StatusCode -lt 300) -or $null -eq $r.Bytes) {
            $err = if ($r.Error) { $r.Error } else { "HTTP $($r.StatusCode)" }
            Write-Warning "EPSS request failed: $err"
            break
        }
        try {
            $json = [System.Text.Encoding]::UTF8.GetString($r.Bytes) | ConvertFrom-Json
            $now = [DateTime]::UtcNow.ToString('o')
            foreach ($d in @(Get-ObjectProperty -Item $json -Name 'data')) {
                $id = ([string](Get-ObjectProperty -Item $d -Name 'cve')).ToUpperInvariant()
                if (-not $id) { continue }
                $entry = [PSCustomObject]@{
                    Epss       = [double](Get-ObjectProperty -Item $d -Name 'epss')
                    Percentile = [double](Get-ObjectProperty -Item $d -Name 'percentile')
                    FetchedAt  = $now
                }
                $table[$id] = $entry
                $cacheItems[$id] = $entry
            }
        }
        catch {
            Write-Warning "EPSS response could not be parsed: $($_.Exception.Message)"
            break
        }
        if ($i + $BatchSize -lt $missing.Count) { Start-Sleep -Milliseconds 300 }
    }

    if ($null -ne $State) {
        # Keep the cache bounded: drop entries older than 7 days
        $keep = [ordered]@{}
        foreach ($k in $cacheItems.Keys) {
            $v = $cacheItems[$k]
            $age = 0
            if ($v.PSObject.Properties['FetchedAt']) {
                $age = ([DateTime]::UtcNow - (ConvertTo-DateTime -InputObject ([string]$v.FetchedAt) -Fallback ([DateTime]::MinValue))).TotalDays
            }
            if ($age -lt 7) { $keep[$k] = $v }
        }
        $State.EpssCache = [PSCustomObject]@{
            FetchedAt = [DateTime]::UtcNow.ToString('o')
            Items     = [PSCustomObject]$keep
        }
    }

    return $table
}

# ------------------------------------------------------------
# Notifications
# ------------------------------------------------------------
function Send-WebhookNotification {
    <#
    .SYNOPSIS
        Posts a run summary to an HTTPS webhook (Slack/Teams-compatible JSON).
    #>
    [CmdletBinding()]
    param(
        [string]$Url,

        [int]$NewCount = 0,

        [int]$TotalCount = 0,

        [int]$FeedCount = 0,

        [int]$UnhealthyCount = 0,

        [int]$KevArticleCount = 0,

        [double]$DurationSeconds = 0,

        [string]$ReportPath = ''
    )

    if ([string]::IsNullOrWhiteSpace($Url)) { return }
    if ($Url -notmatch '^https://') {
        Write-Warning 'Webhook skipped: WebhookUrl must use https://'
        return
    }

    $text = "ThreatRaven run completed: $NewCount new items, $TotalCount total, $FeedCount feeds ($UnhealthyCount unhealthy), $([math]::Round($DurationSeconds, 1))s."
    if ($KevArticleCount -gt 0) { $text += " $KevArticleCount article(s) reference CISA KEV CVEs." }
    if ($ReportPath) { $text += " Report: $([System.IO.Path]::GetFileName($ReportPath))" }

    $body = [ordered]@{ text = $text }
    try {
        Invoke-RestMethod -Uri $Url -Method Post -ContentType 'application/json' -Body ($body | ConvertTo-Json -Compress) -TimeoutSec 15 | Out-Null
    }
    catch {
        Write-Warning "Webhook notification failed: $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function @(
    'Get-ObjectProperty',
    'Get-RegexMatch',
    'Get-CveIdsFromText',
    'Get-MitreIdsFromText',
    'ConvertTo-DateTime',
    'Get-AllTextContent',
    'Get-FeedItemTitle',
    'Get-FeedItemDate',
    'Get-ItemLink',
    'ConvertTo-NormalizedUrl',
    'Test-UrlSafety',
    'ConvertTo-JavaScriptString',
    'ConvertTo-EmbeddedJson',
    'ConvertFrom-FeedContent',
    'Get-WebResponseHeader',
    'Get-FeedHttpClient',
    'Invoke-FeedRequest',
    'Get-HttpStatusAction',
    'Get-RetryAfterSeconds',
    'Invoke-FeedFetchWithRetry',
    'Merge-ConfigDefaults',
    'ConvertTo-FeedDefinition',
    'Get-FeedDefinitions',
    'Test-Configuration',
    'Initialize-Configuration',
    'Get-FeedStatusLabel',
    'Get-FeedHealthReport',
    'Export-FeedHealthReport',
    'Save-RunConfiguration',
    'Initialize-ThreatRavenState',
    'Save-ThreatRavenState',
    'Update-FeedRunHistory',
    'Get-ThreatRavenHistoryItems',
    'Get-NvdCves',
    'Get-CisaKev',
    'Get-EpssScores',
    'Send-WebhookNotification'
)
