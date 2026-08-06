# Pester tests for FeedHelpers.psm1
# Compatible with Pester 3.x and 5.x (run: Invoke-Pester .\Tests\FeedHelpers.Tests.ps1)

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path (Split-Path -Parent $here) 'FeedHelpers.psm1'
Import-Module $modulePath -Force

Describe 'Report template CSP safety' {
    It 'has no inline event handler attributes (blocked by nonce CSP)' {
        $template = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $here) 'assets\report-template.html') -Raw
        $template | Should Not Match '\son(?:click|change|keyup|keydown|input)=["'']'
    }

    It 'wires interactions through initInteractions' {
        $template = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $here) 'assets\report-template.html') -Raw
        $template | Should Match 'function initInteractions'
        $template | Should Match 'addEventListener'
    }
}

Describe 'ConvertTo-JavaScriptString' {
    It 'escapes backslashes and quotes' {
        $result = ConvertTo-JavaScriptString -Text 'a\b"c'
        $result | Should Be 'a\\b\"c'
    }

    It 'neutralizes closing script tags' {
        $result = ConvertTo-JavaScriptString -Text '</script><script>alert(1)</script>'
        $result | Should Not Match '</script'
    }

    It 'escapes control characters as unicode escapes' {
        $result = ConvertTo-JavaScriptString -Text ([string][char]1)
        $result | Should Be '\u0001'
    }
}

Describe 'ConvertTo-NormalizedUrl' {
    It 'strips tracking parameters and fragments' {
        $result = ConvertTo-NormalizedUrl -Url 'https://Example.com/path/?utm_source=x&id=5#frag'
        $result | Should Be 'https://example.com/path?id=5'
    }

    It 'lowercases the host' {
        $result = ConvertTo-NormalizedUrl -Url 'HTTPS://NEWS.EXAMPLE/Article'
        $result | Should Be 'https://news.example/Article'
    }

    It 'returns empty for empty input' {
        ConvertTo-NormalizedUrl -Url '' | Should Be ''
    }
}

Describe 'Test-UrlSafety' {
    It 'rejects javascript and data URIs' {
        Test-UrlSafety -Url 'javascript:alert(1)' | Should Be $false
        Test-UrlSafety -Url 'data:text/html,<script>1</script>' | Should Be $false
    }

    It 'accepts http and https' {
        Test-UrlSafety -Url 'https://example.com/a' | Should Be $true
        Test-UrlSafety -Url 'http://example.com/a' | Should Be $true
    }
}

Describe 'Get-AllTextContent' {
    It 'strips HTML and decodes entities' {
        $item = [PSCustomObject]@{
            title       = 'Hello &amp; <b>world</b>'
            description = 'CVE-2026-0001 &lt;script&gt;x&lt;/script&gt; &rsquo;'
        }
        $result = Get-AllTextContent -Item $item
        $result | Should Be ('Hello & world CVE-2026-0001 <script>x</script> ' + [char]0x2019)
    }
}

Describe 'Get-FeedItemDate' {
    It 'parses RFC1123 dates with invariant culture' {
        $item = [PSCustomObject]@{ pubDate = 'Tue, 04 Aug 2026 13:32:00 GMT' }
        $result = Get-FeedItemDate -Item $item
        $result.Year | Should Be 2026
        $result.Month | Should Be 8
        $result.Day | Should Be 4
    }

    It 'falls back to Atom updated field' {
        $item = [PSCustomObject]@{ published = ''; updated = '2026-08-04T10:00:00Z' }
        $result = Get-FeedItemDate -Item $item
        $result.Year | Should Be 2026
    }
}

Describe 'Get-ItemLink' {
    It 'extracts a standard RSS link' {
        $xml = @'
<?xml version="1.0"?>
<rss version="2.0"><channel><item><title>T</title><link>https://a.example/x</link></item></channel></rss>
'@
        $parsed = ConvertFrom-FeedContent -Content $xml
        $result = Get-ItemLink -Item $parsed.Items[0] -FeedUrl 'https://a.example/feed'
        $result | Should Be 'https://a.example/x'
    }

    It 'extracts a Reddit comments link from content' {
        $item = [PSCustomObject]@{
            title       = 'Post'
            description = 'see <a href="https://www.reddit.com/r/netsec/comments/abc/thread">here</a>'
        }
        $result = Get-ItemLink -Item $item -FeedUrl 'https://www.reddit.com/r/netsec/.rss'
        $result | Should Be 'https://www.reddit.com/r/netsec/comments/abc/thread'
    }
}

Describe 'ConvertFrom-FeedContent' {
    It 'parses multiple RSS items' {
        $xml = @'
<?xml version="1.0"?>
<rss version="2.0"><channel>
<item><title>A</title><link>https://a.example/1</link></item>
<item><title>B</title><link>https://a.example/2</link></item>
</channel></rss>
'@
        $result = ConvertFrom-FeedContent -Content $xml
        $result.Error | Should Be $null
        $result.Items.Count | Should Be 2
    }

    It 'handles feeds with a DOCTYPE (DTD ignored, no expansion)' {
        $xml = @'
<?xml version="1.0"?>
<!DOCTYPE rss [<!ENTITY x "evil">]>
<rss version="2.0"><channel><item><title>&amp; test</title><link>https://a.example/1</link></item></channel></rss>
'@
        $result = ConvertFrom-FeedContent -Content $xml
        $result.Error | Should Be $null
        $result.Items.Count | Should Be 1
    }

    It 'reports no items for an empty feed' {
        $result = ConvertFrom-FeedContent -Content '<rss version="2.0"><channel><title>x</title></channel></rss>'
        $result.Error | Should Be 'No items'
    }

    It 'detects HTML pages masquerading as feeds' {
        $result = ConvertFrom-FeedContent -Content '<!doctype html><html><head><title>x</title></head><body></body></html>'
        $result.Error | Should Be 'Feed returned HTML instead of XML (URL may point to a webpage)'
    }
}

Describe 'Merge-ConfigDefaults' {
    It 'fills missing settings with defaults' {
        $cfg = @{ Keywords = @('x'); MitreKeywords = @{}; Feeds = @('https://a'); UserAgents = @('ua'); AllowedUrlPatterns = @('^https?://') } |
            ConvertTo-Json | ConvertFrom-Json
        $result = Merge-ConfigDefaults -Config $cfg
        $result.Settings.ThrottleLimit | Should Be 10
        $result.Settings.VulnDays | Should Be 7
        $result.SchemaVersion | Should Be 1
    }
}

Describe 'Test-Configuration' {
    It 'accepts a valid configuration' {
        $cfg = @{
            SchemaVersion    = 1
            Settings         = @{ ThrottleLimit = 4; MaxRetries = 2 }
            Keywords         = @('k')
            MitreKeywords    = @{ T1566 = @{ Name = 'Phishing'; Keywords = @('phish') } }
            Feeds            = @('https://a.example/feed')
            UserAgents       = @('ua')
            AllowedUrlPatterns = @('^https?://')
        } | ConvertTo-Json | ConvertFrom-Json
        $cfg = Merge-ConfigDefaults -Config $cfg
        Test-Configuration -Config $cfg | Should Be $true
    }

    It 'rejects an empty feeds array' {
        $cfg = @{
            Settings = @{}; Keywords = @('k'); MitreKeywords = @{}
            Feeds = @(); UserAgents = @('ua'); AllowedUrlPatterns = @('^https?://')
        } | ConvertTo-Json | ConvertFrom-Json
        $cfg = Merge-ConfigDefaults -Config $cfg
        { Test-Configuration -Config $cfg } | Should Throw
    }

    It 'rejects a MITRE entry without keywords' {
        $cfg = @{
            Settings = @{}; Keywords = @('k')
            MitreKeywords = @{ T1566 = @{ Name = 'Phishing'; Keywords = @() } }
            Feeds = @('https://a.example/feed'); UserAgents = @('ua'); AllowedUrlPatterns = @('^https?://')
        } | ConvertTo-Json | ConvertFrom-Json
        $cfg = Merge-ConfigDefaults -Config $cfg
        { Test-Configuration -Config $cfg } | Should Throw
    }
}

Describe 'ThreatRavenState' {
    It 'round-trips items through save and load' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('tr_state_' + [guid]::NewGuid().ToString('N') + '.json')
        try {
            $state = Initialize-ThreatRavenState -Path $tmp
            $state.Items['https://a.example/1'] = [PSCustomObject]@{
                Normalized = 'https://a.example/1'
                Date       = (Get-Date).ToString('o')
                Source     = 'https://a.example/feed'
                Title      = 'Test'
                Keywords   = 'Malware'
                MitreTechniques = ''
                Link       = 'https://a.example/1'
                FirstSeen  = (Get-Date).ToString('o')
                LastSeen   = (Get-Date).ToString('o')
            }
            Save-ThreatRavenState -State $state -Path $tmp

            $loaded = Initialize-ThreatRavenState -Path $tmp
            $loaded.Items.Count | Should Be 1
            $loaded.Items['https://a.example/1'].Title | Should Be 'Test'
        }
        finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }

    It 'returns only history items within the requested window' {
        $state = [PSCustomObject]@{
            Items = @{
                'https://a.example/recent' = [PSCustomObject]@{
                    Normalized = 'https://a.example/recent'
                    Date       = (Get-Date).ToString('o')
                    Link       = 'https://a.example/recent'
                }
                'https://a.example/old' = [PSCustomObject]@{
                    Normalized = 'https://a.example/old'
                    Date       = (Get-Date).AddDays(-30).ToString('o')
                    Link       = 'https://a.example/old'
                }
            }
        }
        $history = @(Get-ThreatRavenHistoryItems -State $state -Days 7)
        $history.Count | Should Be 1
        $history[0].Link | Should Be 'https://a.example/recent'
    }
}

Describe 'Get-WebResponseHeader' {
    It 'reads headers from a dictionary-style response' {
        $response = [PSCustomObject]@{
            Headers = @{ 'ETag' = '"abc123"'; 'Last-Modified' = 'Wed, 05 Aug 2026 16:30:00 GMT' }
        }
        Get-WebResponseHeader -Response $response -Name 'ETag' | Should Be '"abc123"'
        Get-WebResponseHeader -Response $response -Name 'Last-Modified' | Should Be 'Wed, 05 Aug 2026 16:30:00 GMT'
        Get-WebResponseHeader -Response $response -Name 'X-Missing' | Should Be $null
    }

    It 'reads Retry-After from a WebHeaderCollection' {
        $headers = [System.Net.WebHeaderCollection]::new()
        $headers.Add('Retry-After', '5')
        $response = [PSCustomObject]@{ Headers = $headers }
        Get-WebResponseHeader -Response $response -Name 'Retry-After' | Should Be '5'
    }
}
