# ============================================================
# FeedHelpers.psm1 - Shared helper functions for ThreatRaven.ps1
# Version: 4.1
#
# v4.1 changes:
#  - ConvertFrom-FeedContent accepts raw bytes so XmlReader detects the
#    real encoding (fixes mojibake on PS 5.1 when charset is missing)
#  - Atomic state saves (temp file + File.Replace, .bak of last good state)
#  - Get-FeedStatusLabel: single source of truth for feed health status
#  - Test-UrlSafety: scheme blocklist anchored to start of URL (no more
#    false positives on query strings containing "data:" etc.)
#  - NVD cache invalidated when KeywordFilter/MaxResults change
#  - Run-config snapshot redacts NvdApiKey and WebhookUrl
#  - Renamed internal Get-ObjectProperty (shadowed a built-in cmdlet)
#
# v4.0 changes:
#  - Strict-mode safe property access for XML/RSS duck typing
#  - WebUtility.HtmlDecode for complete entity decoding (single pass)
#  - Fixed duplicate content:encoded extraction
#  - Invariant-culture RFC822/3339 date parsing (pubDate/published/updated/dc:date)
#  - URL normalization for deduplication (fragment/tracking-param strip)
#  - Secure XML parsing via XmlReader (DTD ignored, resolver disabled, size caps)
#  - Config schema defaults merge + stricter validation
#  - Persistent state file support (seen links, feed cache, health history, NVD cache)
#  - Server-side NVD CVE fetching with pagination and rate-limit handling
#  - Webhook notification support
# ============================================================

#Requires -Version 5.1

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

function ConvertTo-DateTime {
    <#
    .SYNOPSIS
        Parses a date string using invariant culture and common feed formats.
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
    $styles = [System.Globalization.DateTimeStyles]::AllowWhiteSpaces
    $formats = @(
        'r',
        'ddd, d MMM yyyy HH:mm:ss zzz',
        'ddd, d MMM yyyy HH:mm zzz',
        'yyyy-MM-ddTHH:mm:sszzz',
        'yyyy-MM-ddTHH:mm:ssZ',
        'yyyy-MM-ddTHH:mm:ss',
        'yyyy-MM-dd HH:mm:ss',
        'yyyy-MM-dd',
        'MM/dd/yyyy HH:mm:ss',
        'ddd MMM d HH:mm:ss yyyy'
    )

    $parsed = [DateTime]::MinValue
    $trimmed = $InputObject.Trim()
    foreach ($f in $formats) {
        if ([DateTime]::TryParseExact($trimmed, $f, $ci, $styles, [ref]$parsed)) {
            return $parsed
        }
    }
    if ([DateTime]::TryParse($trimmed, $ci, $styles, [ref]$parsed)) {
        return $parsed
    }
    return $Fallback
}

function Get-AllTextContent {
    <#
    .SYNOPSIS
        Extracts and combines text content from RSS/Atom feed items.
    .DESCRIPTION
        Parses XML feed items and extracts text from title, description,
        content, and other fields. Strips HTML tags and decodes all
        HTML entities in a single pass via WebUtility.HtmlDecode.
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

    # Strip HTML tags, then decode every HTML entity in a single pass.
    $combined = [regex]::Replace($combined, '<[^>]*>', ' ')
    $combined = [System.Net.WebUtility]::HtmlDecode($combined)
    $combined = [regex]::Replace($combined, '\s+', ' ')

    return $combined.Trim()
}

function Get-FeedItemTitle {
    <#
    .SYNOPSIS
        Safely extracts the title of a feed item.
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
    return $title.Trim()
}

function Get-FeedItemDate {
    <#
    .SYNOPSIS
        Parses the publication date of a feed item using invariant culture.
    .DESCRIPTION
        Checks pubDate, published, updated, dc:date and date fields and
        parses RFC822/RFC3339 formats regardless of the host locale.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Item
    )

    $raw = $null
    foreach ($name in @('pubDate', 'published', 'updated', 'dc:date', 'date')) {
        $value = Get-ObjectProperty -Item $Item -Name $name
        if ($null -eq $value) { continue }

        if ($value -is [string]) {
            $raw = $value.Trim()
            break
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
    return ConvertTo-DateTime -InputObject $raw -Fallback ([DateTime]::UtcNow)
}

function Get-ItemLink {
    <#
    .SYNOPSIS
        Extracts the article link from an RSS/Atom feed item.
    .DESCRIPTION
        Handles special cases for specific feeds (Reddit, CISA, 0patch,
        any.run, Talos) and falls back to standard RSS/Atom link extraction.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Item,

        [Parameter(Mandatory)]
        [string]$FeedUrl
    )

    $extractedLink = $null

    $getText = {
        param($Prop)
        if ($null -eq $Prop) { return $null }
        if ($Prop -is [string]) { return $Prop }
        elseif ($Prop.PSObject.Properties['#text']) { return [string]$Prop.'#text' }
        elseif ($Prop.PSObject.Properties['href']) { return [string]$Prop.href }
        elseif ($Prop.PSObject.Properties['InnerText']) { return [string]$Prop.InnerText }
        return $null
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

        $contentToSearch = ''
        $cVal = Get-ObjectProperty -Item $Item -Name 'content'
        $dVal = Get-ObjectProperty -Item $Item -Name 'description'
        if ($null -ne $cVal) { $contentToSearch += (& $getText $cVal) }
        if ($null -ne $dVal) { $contentToSearch += ' ' + (& $getText $dVal) }
        if ($contentToSearch -match 'href="(https?://blog\.0patch\.com/\d{4}/\d{2}/[^"]+\.html)"') {
            return $Matches[1].Trim()
        }
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
            if ($null -ne $idVal) {
                $extractedLink = if ($idVal -is [string]) { $idVal } else { (& $getText $idVal) }
            }
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
        $dVal = Get-ObjectProperty -Item $Item -Name 'description'
        $cVal = Get-ObjectProperty -Item $Item -Name 'content'
        if ($null -ne $dVal) { $contentToSearch += (& $getText $dVal) }
        if ($null -ne $cVal) { $contentToSearch += ' ' + (& $getText $cVal) }
        if ($contentToSearch -match 'href="(https?://any\.run/[^"]+)"') {
            return $Matches[1].Trim()
        }
    }

    # Reddit special handling
    if ($FeedUrl -match 'reddit\.com') {
        $redditPostLink = $null

        $linkVal = Get-ObjectProperty -Item $Item -Name 'link'
        $linkStr = if ($linkVal -is [string]) { $linkVal } elseif ($null -ne $linkVal) { (& $getText $linkVal) } else { $null }
        if ($linkStr -match 'reddit\.com/r/[^/]+/comments/') {
            $redditPostLink = $linkStr
        }
        else {
            $idVal = Get-ObjectProperty -Item $Item -Name 'id'
            $idStr = if ($idVal -is [string]) { $idVal } elseif ($null -ne $idVal) { (& $getText $idVal) } else { $null }
            if ($idStr -match 'reddit\.com/r/[^/]+/comments/') {
                $redditPostLink = $idStr
            }
            else {
                $guidVal = Get-ObjectProperty -Item $Item -Name 'guid'
                if ($null -ne $guidVal) {
                    $gv = & $getText $guidVal
                    if ($gv -match 'reddit\.com/r/[^/]+/comments/') { $redditPostLink = $gv }
                }
            }
        }

        if (-not $redditPostLink) {
            $contentToSearch = ''
            $cVal = Get-ObjectProperty -Item $Item -Name 'content'
            $dVal = Get-ObjectProperty -Item $Item -Name 'description'
            if ($null -ne $cVal) { $contentToSearch += (& $getText $cVal) }
            if ($null -ne $dVal) { $contentToSearch += ' ' + (& $getText $dVal) }

            if ($contentToSearch) {
                if ($contentToSearch -match 'href="(https?://[^"]*reddit\.com/r/[^/]+/comments/[^"]*)"') {
                    $redditPostLink = $Matches[1].Trim()
                }
                elseif ($contentToSearch -match '(https?://[^\s<>"]*reddit\.com/r/[^/]+/comments/[^\s<>"]*)') {
                    $redditPostLink = $Matches[1].Trim()
                }
            }
        }

        if ($redditPostLink) { return $redditPostLink.Trim() }
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
        elseif ($value.PSObject.Properties['InnerText']) {
            $candidate = [string]$value.InnerText
        }
        elseif ($value -is [System.Collections.IEnumerable]) {
            foreach ($linkItem in $value) {
                $c = $null
                if ($linkItem -is [string]) {
                    $c = $linkItem
                }
                elseif ($null -ne $linkItem -and $linkItem.PSObject.Properties['href']) {
                    $c = [string]$linkItem.href
                }
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

    # CISA special handling
    if ((-not $extractedLink -or $extractedLink -eq $FeedUrl) -and $FeedUrl -match 'cisa\.gov') {
        $idVal = Get-ObjectProperty -Item $Item -Name 'id'
        $guidVal = Get-ObjectProperty -Item $Item -Name 'guid'
        $advisoryId = $null
        if ($null -ne $idVal) {
            $advisoryId = if ($idVal -is [string]) { $idVal } else { (& $getText $idVal) }
        }
        elseif ($null -ne $guidVal) {
            $advisoryId = if ($guidVal -is [string]) { $guidVal } else { (& $getText $guidVal) }
        }
        if ($advisoryId -match '(AA|ICSA?|ICS-?ALERT|CSAF)-\d{2}-\d{3,6}') {
            $extractedLink = "https://www.cisa.gov/news-events/cybersecurity-advisories/$advisoryId"
        }
    }

    # Talos special handling
    if ((-not $extractedLink -or $extractedLink -eq $FeedUrl) -and $FeedUrl -match 'talosintelligence|feedburner/Talos') {
        $dVal = Get-ObjectProperty -Item $Item -Name 'description'
        if ($null -ne $dVal) {
            $dText = if ($dVal -is [string]) { $dVal } else { (& $getText $dVal) }
            if ($dText -match 'href="(https?://[^"]+)"') {
                $extractedLink = $Matches[1]
            }
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
        $host = $uri.Host.ToLowerInvariant()
        $path = $uri.AbsolutePath
        if ($path.Length -gt 1 -and $path.EndsWith('/')) { $path = $path.TrimEnd('/') }

        $query = ''
        if ($uri.Query) {
            $kept = @()
            foreach ($pair in $uri.Query.TrimStart('?').Split('&')) {
                if ($pair -eq '') { continue }
                $name = ($pair -split '=', 2)[0].ToLowerInvariant()
                if ($name -notmatch '^(utm_.*|gclid|fbclid|mc_cid|mc_eid|ref|source|spm|wkey)$') {
                    $kept += $pair
                }
            }
            if ($kept.Count -gt 0) { $query = '?' + ($kept -join '&') }
        }

        return "${scheme}://${host}${path}${query}"
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

        # Block dangerous schemes (anchored: a query string containing
        # "data:" must not reject an otherwise valid http(s) URL) and
        # HTML injection fragments anywhere in the URL.
        if ($Url -match '^\s*(javascript|data|vbscript|file|ftp):' -or
            $Url -match '<script|<iframe|onerror=|onload=') {
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
        Escapes backslashes, quotes, control characters, JS line
        separators, and closing script tags so the output is safe to
        embed inside a <script> block.
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
    $escaped = $escaped.Replace([string][char]0x2028, '\u2028')
    $escaped = $escaped.Replace([string][char]0x2029, '\u2029')
    $escaped = $escaped -replace '</script', '<\/script'
    $escaped = [regex]::Replace($escaped, '[\u0000-\u001F\u007F]', {
        param($m)
        '\u{0:X4}' -f [int][char]$m.Value[0]
    })

    return $escaped
}

function ConvertFrom-FeedContent {
    <#
    .SYNOPSIS
        Parses RSS/Atom/RDF XML safely and returns feed items.
    .DESCRIPTION
        Uses XmlReader with DTD processing ignored, no external resolver,
        and entity/document size limits. Retries once after stripping BOM
        and non-printable control characters.

        Prefer passing -Bytes: XmlReader then detects the document's real
        encoding from the BOM / XML prolog, which avoids mojibake when the
        HTTP response was decoded with the wrong charset (a common problem
        on PowerShell 5.1 when servers omit charset in Content-Type).
    .OUTPUTS
        PSCustomObject with Items (XmlElement[]) and Error (string or $null).
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
        # Sniff the head for HTML masquerading as a feed (lenient UTF-8
        # decode is fine here: '<html'/'<!doctype' are ASCII).
        $sniffLen = [Math]::Min(512, $Bytes.Length)
        $head = [System.Text.Encoding]::UTF8.GetString($Bytes, 0, $sniffLen)
        if (($head -replace "^\uFEFF", '').TrimStart() -match '^<(html|!doctype)') {
            $result.Error = 'Feed returned HTML instead of XML (URL may point to a webpage)'
            return $result
        }
    }
    else {
        if ([string]::IsNullOrWhiteSpace($Content)) {
            $result.Error = 'Empty content'
            return $result
        }

        # Detect HTML pages masquerading as feeds (clear error instead of a cryptic XML parse failure)
        if ($Content.TrimStart() -match '^<(html|!doctype)') {
            $result.Error = 'Feed returned HTML instead of XML (URL may point to a webpage)'
            return $result
        }
    }

    $newSettings = {
        $settings = [System.Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Ignore
        $settings.XmlResolver = $null
        $settings.MaxCharactersFromEntities = 10240
        $settings.MaxCharactersInDocument = 52428800
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
        # XmlReader over a raw stream auto-detects encoding (BOM/prolog).
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

    $doc = $null
    if ($useBytes) {
        try {
            $ms = [System.IO.MemoryStream]::new($Bytes)
            try { $doc = & $parseStream $ms }
            finally { $ms.Dispose() }
        }
        catch {
            # Fall back: decode as UTF-8, strip BOM and control characters,
            # and retry via the text path.
            try {
                $text = [System.Text.Encoding]::UTF8.GetString($Bytes)
                $cleaned = $text -replace "^\uFEFF", '' -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
                $doc = & $parse $cleaned
            }
            catch {
                $result.Error = "XML parse error: $($_.Exception.Message)"
                return $result
            }
        }
    }
    else {
        try {
            $doc = & $parse $Content
        }
        catch {
            try {
                $cleaned = $Content -replace "^\uFEFF", '' -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
                $doc = & $parse $cleaned
            }
            catch {
                $result.Error = "XML parse error: $($_.Exception.Message)"
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

function Get-WebResponseHeader {
    <#
    .SYNOPSIS
        Reads a response header from Invoke-WebRequest results,
        compatible with both PowerShell 5.1 and 7+ header types.
    #>
    [CmdletBinding()]
    param(
        $Response,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Response) { return $null }
    $headers = $Response.Headers
    if ($null -eq $headers) { return $null }

    try {
        if ($headers -is [System.Collections.IDictionary]) {
            foreach ($key in @($headers.Keys)) {
                if ([string]$key -ieq $Name) {
                    return [string]$headers[$key]
                }
            }
            return $null
        }

        if ($headers -is [System.Net.WebHeaderCollection]) {
            $value = $headers[$Name]
            if ($null -eq $value) { return $null }
            return [string]$value
        }

        # HttpHeaders (PowerShell 7+)
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
        FeedTimeoutSeconds        = 25
        MaxRetries                = 3
        RetryBaseDelaySeconds     = 2
        LogLevel                  = 'Info'
        ValidateCertificates      = $true
        ExportHealthReport        = $false
        NvdEnabled                = $true
        NvdApiKey                 = ''
        NvdMaxResults             = 2000
        NvdCacheHours             = 6
        NvdKeywordFilter          = $false
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

    if (-not $Config.PSObject.Properties['Settings']) {
        $Config | Add-Member -NotePropertyName Settings -NotePropertyValue ([PSCustomObject]@{}) -Force
    }

    foreach ($key in $defaults.Keys) {
        $existing = $Config.Settings.PSObject.Properties[$key]
        if ($null -eq $existing -or $null -eq $existing.Value) {
            $Config.Settings | Add-Member -NotePropertyName $key -NotePropertyValue $defaults[$key] -Force
        }
    }

    if (-not $Config.PSObject.Properties['SchemaVersion']) {
        $Config | Add-Member -NotePropertyName SchemaVersion -NotePropertyValue 1 -Force
    }

    return $Config
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
        if ([string]::IsNullOrWhiteSpace($feed)) {
            throw "Configuration Feeds contains an empty entry"
        }
    }

    foreach ($tid in $Config.MitreKeywords.PSObject.Properties.Name) {
        $entry = $Config.MitreKeywords.$tid
        if (-not $entry.PSObject.Properties['Name'] -or [string]::IsNullOrWhiteSpace([string]$entry.Name)) {
            throw "MITRE entry '$tid' is missing Name"
        }
        $validKeywords = @()
        foreach ($k in $entry.Keywords) {
            if ($null -ne $k -and -not [string]::IsNullOrWhiteSpace([string]$k)) {
                $validKeywords += $k
            }
        }
        if (-not $entry.PSObject.Properties['Keywords'] -or $validKeywords.Count -eq 0) {
            throw "MITRE entry '$tid' is missing Keywords"
        }
    }

    $s = $Config.Settings
    if ($s.ThrottleLimit -lt 1)       { throw "ThrottleLimit must be greater than 0" }
    if ($s.MaxRetries -lt 1)          { throw "MaxRetries must be greater than 0" }
    if ($s.FeedTimeoutSeconds -lt 1)  { throw "FeedTimeoutSeconds must be greater than 0" }
    if ($s.RetryBaseDelaySeconds -lt 0) { throw "RetryBaseDelaySeconds must be >= 0" }
    if ($s.VulnDays -lt 1)            { throw "VulnDays must be greater than 0" }
    if ($s.GlobalTimeoutSeconds -lt 60) { throw "GlobalTimeoutSeconds must be >= 60" }
    if ($s.NvdMaxResults -lt 1)       { throw "NvdMaxResults must be greater than 0" }
    if ($s.ReportHistoryDays -lt 0)   { throw "ReportHistoryDays must be >= 0" }
    if ($s.StateRetentionDays -lt 1)  { throw "StateRetentionDays must be greater than 0" }
    if ($s.LogLevel -notin @('Debug', 'Info', 'Warning', 'Error')) {
        throw "LogLevel must be one of: Debug, Info, Warning, Error"
    }

    if ($s.PSObject.Properties['HostRequestIntervalMsOverrides'] -and $null -ne $s.HostRequestIntervalMsOverrides) {
        foreach ($ov in $s.HostRequestIntervalMsOverrides.PSObject.Properties) {
            $ovInt = 0
            if (-not [int]::TryParse([string]$ov.Value, [ref]$ovInt) -or $ovInt -lt 0) {
                throw "HostRequestIntervalMsOverrides['$($ov.Name)'] must be a non-negative integer (milliseconds)"
            }
        }
    }

    if ($Config.PSObject.Properties['SchemaVersion'] -and $Config.SchemaVersion -gt 1) {
        Write-Warning "Config SchemaVersion $($Config.SchemaVersion) is newer than supported (1); some settings may be ignored"
    }

    Write-Verbose "Configuration validation passed"
    return $true
}

function Initialize-Configuration {
    <#
    .SYNOPSIS
        Loads, merges defaults into, and validates the configuration file.
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
        $null = Test-Configuration -Config $config
        return $config
    }
    catch {
        throw "Failed to parse configuration: $($_.Exception.Message)"
    }
}

function Get-FeedStatusLabel {
    <#
    .SYNOPSIS
        Classifies a feed's health from its success/failure counters.
    .DESCRIPTION
        Single source of truth for feed status so the console summary,
        the exported health report and the HTML report always agree:
        unhealthy = failed and never succeeded this run,
        degraded  = succeeded but with more than 2 failures,
        healthy   = everything else.
    .OUTPUTS
        [string] 'healthy', 'degraded' or 'unhealthy'.
    #>
    [CmdletBinding()]
    param(
        [int]$SuccessCount = 0,

        [int]$FailureCount = 0
    )

    if ($FailureCount -gt 0 -and $SuccessCount -eq 0) { return 'unhealthy' }
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

        $label = Get-FeedStatusLabel -SuccessCount $health.SuccessCount -FailureCount $health.FailureCount
        if ($label -eq 'healthy') {
            $healthy++
        }
        else {
            if ($label -eq 'unhealthy') { $unhealthy++ } else { $degraded++ }
            $unhealthyList.Add([PSCustomObject]@{
                Feed        = $entry.Key
                Host        = $health.Host
                Status      = $label.ToUpperInvariant()
                Failures    = $health.FailureCount
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

    $exportData = [PSCustomObject]@{
        GeneratedAt = $report.Timestamp
        Summary = [PSCustomObject]@{
            Healthy       = $report.Healthy
            Degraded      = $report.Degraded
            Unhealthy     = $report.Unhealthy
            TotalSuccess  = $report.TotalSuccess
            TotalFailures = $report.TotalFailures
        }
        Feeds = @()
    }

    foreach ($entry in $FeedHealth.GetEnumerator()) {
        $avgMs = 0.0
        if ($entry.Value.ResponseTimes -is [System.Collections.Generic.List[double]] -and $entry.Value.ResponseTimes.Count -gt 0) {
            $avgMs = [math]::Round(($entry.Value.ResponseTimes | Measure-Object -Average).Average, 1)
        }
        $exportData.Feeds += [PSCustomObject]@{
            FeedUrl        = $entry.Key
            Host           = $entry.Value.Host
            SuccessCount   = $entry.Value.SuccessCount
            FailureCount   = $entry.Value.FailureCount
            TotalItems     = $entry.Value.TotalItems
            TotalMatches   = $entry.Value.TotalMatches
            AvgResponseMs  = $avgMs
            LastError      = $entry.Value.LastError
            LastChecked    = $entry.Value.LastChecked
        }
    }

    $exportData | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $Path -Encoding UTF8
    Write-Verbose "Feed health report exported to: $Path"
}

function Save-RunConfiguration {
    <#
    .SYNOPSIS
        Saves the current run configuration for audit purposes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Config,

        [Parameter(Mandatory)]
        [string]$Path,

        [string]$StatePath = ''
    )

    # Copy settings with secrets redacted: the snapshot lands in the output
    # directory, which may be shared more widely than config.json.
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
        MitreTechniqueCount = $Config.MitreKeywords.PSObject.Properties.Name.Count
        StateFile           = $StatePath
    }

    $runConfig | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $Path -Encoding UTF8
}

function Initialize-ThreatRavenState {
    <#
    .SYNOPSIS
        Loads (or creates) the persistent state file.
    .DESCRIPTION
        The state file stores seen links (with first/last seen timestamps),
        per-feed HTTP cache metadata (ETag/Last-Modified), NVD cache, and
        feed health history so deduplication and caching survive restarts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [int]$RetentionDays = 90,

        [int]$MaxEntries = 20000
    )

    $state = [PSCustomObject]@{
        SchemaVersion  = 1
        Items          = @{}
        FeedCache      = @{}
        NvdCache       = $null
        HealthHistory  = @()
        UpdatedAt      = (Get-Date).ToString('o')
    }

    if (Test-Path -LiteralPath $Path) {
        try {
            $loaded = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json

            if ($loaded.PSObject.Properties['Items'] -and $null -ne $loaded.Items) {
                $items = @{}
                foreach ($p in $loaded.Items.PSObject.Properties) {
                    $items[$p.Name] = $p.Value
                }
                $state.Items = $items
            }

            if ($loaded.PSObject.Properties['FeedCache'] -and $null -ne $loaded.FeedCache) {
                $cache = @{}
                foreach ($p in $loaded.FeedCache.PSObject.Properties) {
                    $cache[$p.Name] = $p.Value
                }
                $state.FeedCache = $cache
            }

            if ($loaded.PSObject.Properties['NvdCache'] -and $null -ne $loaded.NvdCache) {
                $state.NvdCache = $loaded.NvdCache
            }

            if ($loaded.PSObject.Properties['HealthHistory']) {
                $state.HealthHistory = @($loaded.HealthHistory)
            }
        }
        catch {
            $bak = "$Path.bak"
            Copy-Item -LiteralPath $Path -Destination $bak -Force -ErrorAction SilentlyContinue
            Write-Warning "State file was corrupt and has been backed up to ${bak}: $($_.Exception.Message)"
        }
    }

    return $state
}

function Save-ThreatRavenState {
    <#
    .SYNOPSIS
        Prunes and persists the state file.
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

    $now = Get-Date
    $cutoff = $now.AddDays(-$RetentionDays)
    $items = $State.Items

    if ($items -is [hashtable]) {
        foreach ($key in @($items.Keys)) {
            $lastSeen = ConvertTo-DateTime -InputObject ([string]$items[$key].LastSeen) -Fallback $now
            if ($lastSeen -lt $cutoff) {
                $items.Remove($key)
            }
        }

        if ($items.Count -gt $MaxEntries) {
            $sorted = @($items.GetEnumerator() |
                Sort-Object { ConvertTo-DateTime -InputObject ([string]$_.Value.LastSeen) -Fallback $now } -Descending)
            $toRemove = $sorted[$MaxEntries..($sorted.Count - 1)]
            foreach ($entry in $toRemove) {
                $items.Remove($entry.Key)
            }
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

    # Atomic save: write to a temp file, then swap it into place so a crash
    # mid-write can never corrupt the state file. File.Replace also keeps a
    # .bak copy of the last good state.
    $json = $State | ConvertTo-Json -Depth 10
    $tmpPath = "$Path.tmp"
    [System.IO.File]::WriteAllText($tmpPath, $json, [System.Text.UTF8Encoding]::new($false))

    if (Test-Path -LiteralPath $Path) {
        try {
            [System.IO.File]::Replace($tmpPath, $Path, "$Path.bak")
        }
        catch {
            # File.Replace can fail across volumes or on exotic filesystems;
            # fall back to a plain move (still a single-rename swap).
            Move-Item -LiteralPath $tmpPath -Destination $Path -Force
        }
    }
    else {
        Move-Item -LiteralPath $tmpPath -Destination $Path -Force
    }
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

    $cutoff = (Get-Date).AddDays(-$Days)
    $items = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($entry in $State.Items.GetEnumerator()) {
        $item = $entry.Value
        $d = ConvertTo-DateTime -InputObject ([string]$item.Date) -Fallback ([DateTime]::MinValue)
        if ($d -ge $cutoff) {
            $items.Add($item)
        }
    }

    return $items.ToArray()
}

function Get-NvdCves {
    <#
    .SYNOPSIS
        Fetches CVEs published in the last N days from the NVD API.
    .DESCRIPTION
        Runs server-side with pagination, respects NVD rate limits
        (5 requests/30s without an API key, 50/30s with one), supports
        optional keyword correlation filtering, and caches results.
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
        # The cache is only valid when the parameters that shaped it are
        # unchanged; a cache from an older schema (missing these fields)
        # is treated as stale.
        $sameShape = $cached.PSObject.Properties['Days'] -and $cached.Days -eq $Days -and
            $cached.PSObject.Properties['FetchedAt'] -and
            $cached.PSObject.Properties['KeywordFilter'] -and ([bool]$cached.KeywordFilter) -eq $KeywordFilter -and
            $cached.PSObject.Properties['MaxResults'] -and ([int]$cached.MaxResults) -eq $MaxResults
        if ($sameShape) {
            $age = ((Get-Date) - (ConvertTo-DateTime -InputObject ([string]$cached.FetchedAt) -Fallback ([DateTime]::MinValue))).TotalHours
            if ($age -ge 0 -and $age -lt $CacheHours) {
                Write-Verbose "Using cached NVD data (${age} hours old)"
                return $cached
            }
        }
    }

    $end = (Get-Date).ToUniversalTime()
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
            'User-Agent' = 'ThreatRaven/4.1 (APT Intelligence Feed Monitor)'
        }
        if ($ApiKey) { $headers['apiKey'] = $ApiKey }

        $ok = $false
        $attempt = 0
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
        if ($null -eq $resp.totalResults) {
            throw 'Unexpected NVD API response (missing totalResults)'
        }

        $totalResults = [int]$resp.totalResults
        foreach ($v in $resp.vulnerabilities) {
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
            $keywordRx += [regex]::new(
                '\b' + [regex]::Escape($kw) + '\b',
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                [System.Text.RegularExpressions.RegexOptions]::Compiled
            )
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

        if ($null -ne $metrics) {
            $m31 = Get-ObjectProperty -Item $metrics -Name 'cvssMetricV31'
            $m3 = Get-ObjectProperty -Item $metrics -Name 'cvssMetricV3'
            $m2 = Get-ObjectProperty -Item $metrics -Name 'cvssMetricV2'

            if ($null -ne $m31 -and @($m31).Count -gt 0) {
                $severity = [string]$m31[0].cvssData.baseSeverity
                $score = [double]$m31[0].cvssData.baseScore
            }
            elseif ($null -ne $m3 -and @($m3).Count -gt 0) {
                $severity = [string]$m3[0].cvssData.baseSeverity
                $score = [double]$m3[0].cvssData.baseScore
            }
            elseif ($null -ne $m2 -and @($m2).Count -gt 0) {
                $severity = [string]$m2[0].baseSeverity
                $score = [double]$m2[0].cvssData.baseScore
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
                if ($rx.IsMatch($desc)) { $matched = $true; break }
            }
            if (-not $matched) { continue }
        }

        $mapped.Add([PSCustomObject]@{
            id          = [string]$cve.id
            published   = [string]$cve.published
            severity    = $severity
            score       = $score
            description = $desc
        })
    }

    $result = [PSCustomObject]@{
        FetchedAt     = (Get-Date).ToString('o')
        Days          = $Days
        KeywordFilter = $KeywordFilter
        MaxResults    = $MaxResults
        Truncated     = $truncated
        Cves          = $mapped
    }

    if ($null -ne $State) {
        $State.NvdCache = $result
    }

    return $result
}

function Send-WebhookNotification {
    <#
    .SYNOPSIS
        Posts a run summary to a webhook (Slack/Teams-compatible JSON).
    #>
    [CmdletBinding()]
    param(
        [string]$Url,

        [int]$NewCount = 0,

        [int]$TotalCount = 0,

        [int]$FeedCount = 0,

        [double]$DurationSeconds = 0,

        [string]$ReportPath = ''
    )

    if ([string]::IsNullOrWhiteSpace($Url)) { return }

    $text = "ThreatRaven run completed: $NewCount new items, $TotalCount total, $FeedCount feeds, $([math]::Round($DurationSeconds, 1))s."
    if ($ReportPath) { $text += " Report: $ReportPath" }

    $body = [ordered]@{ text = $text }
    try {
        Invoke-RestMethod -Uri $Url -Method Post -ContentType 'application/json' -Body ($body | ConvertTo-Json -Compress) -TimeoutSec 15 | Out-Null
    }
    catch {
        Write-Warning "Webhook notification failed: $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function @(
    'Get-AllTextContent',
    'Get-FeedItemTitle',
    'Get-FeedItemDate',
    'ConvertTo-DateTime',
    'Get-ItemLink',
    'ConvertTo-NormalizedUrl',
    'Test-UrlSafety',
    'ConvertTo-HtmlEscaped',
    'ConvertTo-JavaScriptString',
    'ConvertFrom-FeedContent',
    'Get-WebResponseHeader',
    'Merge-ConfigDefaults',
    'Test-Configuration',
    'Initialize-Configuration',
    'Get-FeedStatusLabel',
    'Get-FeedHealthReport',
    'Export-FeedHealthReport',
    'Save-RunConfiguration',
    'Initialize-ThreatRavenState',
    'Save-ThreatRavenState',
    'Get-ThreatRavenHistoryItems',
    'Get-NvdCves',
    'Send-WebhookNotification'
)
