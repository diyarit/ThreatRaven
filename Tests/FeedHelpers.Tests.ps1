# Pester 5 tests for FeedHelpers.psm1
# Run: Invoke-Pester .\Tests\FeedHelpers.Tests.ps1 -Output Detailed

BeforeAll {
    $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    $script:ModulePath = Join-Path $script:RepoRoot 'FeedHelpers.psm1'
    $script:TemplatePath = Join-Path $script:RepoRoot 'assets\report-template.html'
    Import-Module $script:ModulePath -Force

    function New-TempPath([string]$Prefix) {
        Join-Path ([System.IO.Path]::GetTempPath()) ($Prefix + [guid]::NewGuid().ToString('N') + '.json')
    }
}

Describe 'Report template' {
    BeforeAll { $script:Template = Get-Content -LiteralPath $script:TemplatePath -Raw }

    It 'has no inline event handler attributes (blocked by nonce CSP)' {
        $script:Template | Should -Not -Match '\son(?:click|change|keyup|keydown|input|load|error|mouseover)=["'']'
    }

    It 'wires interactions through initInteractions and reads data from the JSON block' {
        $script:Template | Should -Match 'function initInteractions'
        $script:Template | Should -Match 'addEventListener'
        $script:Template | Should -Match 'id="tr-data"'
        $script:Template | Should -Match '\{\{REPORT_JSON\}\}'
        $script:Template | Should -Match 'id="dayTabs"'
        $script:Template | Should -Match 'id="pager"'
    }

    It 'does not build HTML from data with innerHTML' {
        $script:Template | Should -Not -Match '\.innerHTML\s*[+]?=\s*[^;]*\+'
    }

    It 'uses CSS classes that the stylesheet actually defines for the legend' {
        $script:Template | Should -Match 'class:''leg-c'''
        $script:Template | Should -Match '\.leg-c\{'
    }
}

Describe 'ConvertTo-EmbeddedJson' {
    It 'never emits a raw < so </script and <!-- cannot appear' {
        $json = ConvertTo-EmbeddedJson -InputObject @{ a = '</script><!--<img src=x>'; b = 1 }
        $json | Should -Not -Match '<'
        $json | Should -Match '\\u003c'
    }

    It 'round-trips through a JSON parser' {
        $obj = [ordered]@{ title = 'A "quoted" </script> title'; n = 3; list = @('x', 'y') }
        $json = ConvertTo-EmbeddedJson -InputObject $obj
        $back = $json | ConvertFrom-Json
        $back.title | Should -Be 'A "quoted" </script> title'
        $back.n | Should -Be 3
        @($back.list).Count | Should -Be 2
    }
}

Describe 'ConvertTo-JavaScriptString' {
    It 'escapes backslashes and quotes' {
        ConvertTo-JavaScriptString -Text 'a\b"c' | Should -Be 'a\\b\"c'
    }

    It 'neutralizes closing script tags and angle brackets' {
        $result = ConvertTo-JavaScriptString -Text '</script><script>alert(1)</script>'
        $result | Should -Not -Match '<'
    }

    It 'escapes control characters as unicode escapes' {
        ConvertTo-JavaScriptString -Text ([string][char]1) | Should -Be ('\' + 'u0001')
    }
}

Describe 'ConvertTo-DateTime (UTC normalisation)' {
    It 'returns the same UTC instant for GMT, Z, numeric offsets and named US zones' {
        $expected = [DateTime]::new(2026, 9, 10, 14, 0, 0, [DateTimeKind]::Utc)
        foreach ($s in @(
            'Thu, 10 Sep 2026 14:00:00 GMT',
            'Thu, 10 Sep 2026 14:00:00 +0000',
            'Thu, 10 Sep 2026 10:00:00 EDT',
            'Thu, 10 Sep 2026 07:00:00 PDT',
            '2026-09-10T14:00:00Z',
            '2026-09-10T14:00:00.250Z',
            '2026-09-10T16:00:00+02:00',
            '2026-09-10T09:00:00-05:00'
        )) {
            $d = ConvertTo-DateTime -InputObject $s
            $d.Kind | Should -Be ([DateTimeKind]::Utc) -Because $s
            $d.ToString('yyyy-MM-dd HH:mm:ss') | Should -Be $expected.ToString('yyyy-MM-dd HH:mm:ss') -Because $s
        }
    }

    It 'returns the fallback for garbage' {
        $fb = [DateTime]::new(2000, 1, 1)
        ConvertTo-DateTime -InputObject 'not a date' -Fallback $fb | Should -Be $fb
        ConvertTo-DateTime -InputObject '' -Fallback $fb | Should -Be $fb
    }
}

Describe 'Get-FeedItemDate' {
    It 'parses pubDate and clamps absurd future dates' {
        $d = Get-FeedItemDate -Item ([PSCustomObject]@{ pubDate = 'Tue, 04 Aug 2026 13:32:00 GMT' })
        $d.Year | Should -Be 2026; $d.Month | Should -Be 8; $d.Day | Should -Be 4; $d.Hour | Should -Be 13
        $far = Get-FeedItemDate -Item ([PSCustomObject]@{ pubDate = 'Tue, 04 Aug 2099 13:32:00 GMT' })
        ($far -le [DateTime]::UtcNow.AddMinutes(1)) | Should -BeTrue
    }

    It 'falls back to Atom updated field' {
        $d = Get-FeedItemDate -Item ([PSCustomObject]@{ published = ''; updated = '2026-08-04T10:00:00Z' })
        $d.Year | Should -Be 2026
        $d.Hour | Should -Be 10
    }
}

Describe 'Text extraction' {
    It 'strips HTML and decodes entities' {
        $item = [PSCustomObject]@{
            title       = 'Hello &amp; <b>world</b>'
            description = 'CVE-2026-0001 &lt;script&gt;x&lt;/script&gt; &rsquo;'
        }
        Get-AllTextContent -Item $item | Should -Be ('Hello & world CVE-2026-0001 <script>x</script> ' + [char]0x2019)
    }

    It 'returns plain-text titles (tags stripped, entities decoded)' {
        Get-FeedItemTitle -Item ([PSCustomObject]@{ title = 'A &amp; <em>B</em>' }) | Should -Be 'A & B'
        Get-FeedItemTitle -Item ([PSCustomObject]@{ title = '  ' }) | Should -Be 'Untitled'
    }

    It 'extracts unique upper-cased CVE ids' {
        $ids = @(Get-CveIdsFromText -Text 'cve-2024-3400, CVE-2025-12345 and again CVE-2024-3400; not CVE-24-1')
        $ids | Should -Be @('CVE-2024-3400', 'CVE-2025-12345')
        @(Get-CveIdsFromText -Text '') | Should -HaveCount 0
    }

    It 'extracts explicit ATT&CK technique ids' {
        @(Get-MitreIdsFromText -Text 'maps to T1059.001 and T1566 (T1566)') | Should -Be @('T1059.001', 'T1566')
    }
}

Describe 'Get-ItemLink' {
    It 'extracts a standard RSS link' {
        $xml = '<?xml version="1.0"?><rss version="2.0"><channel><item><title>T</title><link>https://a.example/x</link></item></channel></rss>'
        $parsed = ConvertFrom-FeedContent -Content $xml
        Get-ItemLink -Item $parsed.Items[0] -FeedUrl 'https://a.example/feed' | Should -Be 'https://a.example/x'
    }

    It 'prefers rel="alternate" among Atom links and ignores replies/self/edit' {
        $xml = @'
<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>T</title>
<link rel="replies" type="text/html" href="https://a.example/post/1#comment-form"/>
<link rel="edit" href="https://a.example/edit/1"/>
<link rel="self" href="https://a.example/entries/1"/>
<link rel="alternate" type="text/html" href="https://a.example/post/1"/>
</entry></feed>
'@
        $parsed = ConvertFrom-FeedContent -Content $xml
        Get-ItemLink -Item $parsed.Items[0] -FeedUrl 'https://a.example/feed' | Should -Be 'https://a.example/post/1'
    }

    It 'returns $null instead of the feed URL when an item has no usable link' {
        Get-ItemLink -Item ([PSCustomObject]@{ title = 'no link here' }) -FeedUrl 'https://a.example/feed' | Should -BeNullOrEmpty
        Get-ItemLink -Item ([PSCustomObject]@{ title = 'x'; link = 'https://a.example/feed' }) -FeedUrl 'https://a.example/feed' | Should -BeNullOrEmpty
    }

    It 'extracts a Reddit comments link from content' {
        $item = [PSCustomObject]@{
            title       = 'Post'
            description = 'see <a href="https://www.reddit.com/r/netsec/comments/abc/thread">here</a>'
        }
        Get-ItemLink -Item $item -FeedUrl 'https://www.reddit.com/r/netsec/.rss' | Should -Be 'https://www.reddit.com/r/netsec/comments/abc/thread'
    }

    It 'builds CISA advisory links from the advisory id' {
        $item = [PSCustomObject]@{ title = 'Adv'; guid = 'AA26-123A' }
        Get-ItemLink -Item $item -FeedUrl 'https://www.cisa.gov/cybersecurity-advisories/all.xml' | Should -Be 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-123a'
        $ics = [PSCustomObject]@{ title = 'ICS'; id = 'ICSA-26-045-03' }
        Get-ItemLink -Item $ics -FeedUrl 'https://www.cisa.gov/cybersecurity-advisories/all.xml' | Should -Be 'https://www.cisa.gov/news-events/cybersecurity-advisories/icsa-26-045-03'
    }
}

Describe 'ConvertTo-NormalizedUrl' {
    It 'strips tracking parameters and fragments' {
        ConvertTo-NormalizedUrl -Url 'https://Example.com/path/?utm_source=x&id=5&mkt_tok=abc#frag' | Should -Be 'https://example.com/path?id=5'
    }

    It 'lowercases the host but keeps the path case' {
        ConvertTo-NormalizedUrl -Url 'HTTPS://NEWS.EXAMPLE/Article' | Should -Be 'https://news.example/Article'
    }

    It 'returns empty for empty input' {
        ConvertTo-NormalizedUrl -Url '' | Should -Be ''
    }
}

Describe 'Test-UrlSafety' {
    It 'rejects javascript and data URIs' {
        Test-UrlSafety -Url 'javascript:alert(1)' | Should -BeFalse
        Test-UrlSafety -Url 'data:text/html,<script>1</script>' | Should -BeFalse
    }

    It 'accepts http(s), including query strings containing scheme-like tokens' {
        Test-UrlSafety -Url 'https://example.com/a' | Should -BeTrue
        Test-UrlSafety -Url 'http://example.com/a' | Should -BeTrue
        Test-UrlSafety -Url 'https://example.com/read?next=data:text/plain' | Should -BeTrue
    }

    It 'rejects URLs carrying quotes or angle brackets (attribute/markup injection)' {
        Test-UrlSafety -Url 'https://example.com/a"onmouseover="alert(1)' | Should -BeFalse
        Test-UrlSafety -Url 'https://example.com/a?x=<script>1</script>' | Should -BeFalse
        Test-UrlSafety -Url "https://example.com/a'b" | Should -BeFalse
    }
}

Describe 'ConvertFrom-FeedContent' {
    It 'parses multiple RSS items' {
        $xml = '<?xml version="1.0"?><rss version="2.0"><channel><item><title>A</title><link>https://a.example/1</link></item><item><title>B</title><link>https://a.example/2</link></item></channel></rss>'
        $result = ConvertFrom-FeedContent -Content $xml
        $result.Error | Should -BeNullOrEmpty
        $result.Items.Count | Should -Be 2
    }

    It 'handles feeds with a DOCTYPE (DTD ignored, no expansion)' {
        $xml = '<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY x "evil">]><rss version="2.0"><channel><item><title>&amp; test</title><link>https://a.example/1</link></item></channel></rss>'
        $result = ConvertFrom-FeedContent -Content $xml
        $result.Error | Should -BeNullOrEmpty
        $result.Items.Count | Should -Be 1
    }

    It 'reports no items for an empty feed' {
        (ConvertFrom-FeedContent -Content '<rss version="2.0"><channel><title>x</title></channel></rss>').Error | Should -Be 'No items'
    }

    It 'detects HTML and JSON masquerading as feeds' {
        (ConvertFrom-FeedContent -Content '<!doctype html><html><head><title>x</title></head><body></body></html>').Error | Should -Match 'HTML'
        (ConvertFrom-FeedContent -Bytes ([System.Text.Encoding]::UTF8.GetBytes('<!doctype html><html></html>'))).Error | Should -Match 'HTML'
        (ConvertFrom-FeedContent -Bytes ([System.Text.Encoding]::UTF8.GetBytes('{"items":[]}'))).Error | Should -Match 'JSON'
    }

    It 'honours the declared encoding when parsing bytes' {
        $eAcute = [string][char]0xE9
        $xml = '<?xml version="1.0" encoding="iso-8859-1"?><rss version="2.0"><channel><item><title>Caf' + $eAcute + '</title><link>https://a.example/1</link></item></channel></rss>'
        $bytes = [System.Text.Encoding]::GetEncoding('iso-8859-1').GetBytes($xml)
        $result = ConvertFrom-FeedContent -Bytes $bytes
        $result.Error | Should -BeNullOrEmpty
        $result.Items[0].title | Should -Be ('Caf' + $eAcute)
    }

    It 'repairs unescaped ampersands and stray control characters' {
        $xml = '<?xml version="1.0"?><rss version="2.0"><channel><item><title>A &amp; B</title><link>https://a.example/x?a=1&b=2</link><description>bad ' + [char]7 + ' char</description></item></channel></rss>'
        $result = ConvertFrom-FeedContent -Content $xml
        $result.Error | Should -BeNullOrEmpty
        $result.Items[0].link | Should -Be 'https://a.example/x?a=1&b=2'
        $result.Items[0].title | Should -Be 'A & B'
    }

    It 'reports empty content for an empty byte array' {
        (ConvertFrom-FeedContent -Bytes ([byte[]]@())).Error | Should -Be 'Empty content'
    }
}

Describe 'HTTP retry state machine' {
    It 'classifies status codes and transport errors' {
        Get-HttpStatusAction -StatusCode 200 | Should -Be 'success'
        Get-HttpStatusAction -StatusCode 304 | Should -Be 'unchanged'
        Get-HttpStatusAction -StatusCode 429 | Should -Be 'ratelimit'
        Get-HttpStatusAction -StatusCode 403 | Should -Be 'rotate-ua'
        Get-HttpStatusAction -StatusCode 404 | Should -Be 'permanent'
        Get-HttpStatusAction -StatusCode 451 | Should -Be 'permanent'
        Get-HttpStatusAction -StatusCode 503 | Should -Be 'retry'
        Get-HttpStatusAction -StatusCode 0 -ErrorKind 'dns' | Should -Be 'permanent'
        Get-HttpStatusAction -StatusCode 0 -ErrorKind 'tls' | Should -Be 'permanent'
        Get-HttpStatusAction -StatusCode 0 -ErrorKind 'toolarge' | Should -Be 'permanent'
        Get-HttpStatusAction -StatusCode 0 -ErrorKind 'timeout' | Should -Be 'retry'
    }

    It 'parses Retry-After as seconds or HTTP-date, capped' {
        Get-RetryAfterSeconds -Value '7' | Should -Be 7
        Get-RetryAfterSeconds -Value '900' | Should -Be 60
        Get-RetryAfterSeconds -Value 'nonsense' | Should -Be 0
        Get-RetryAfterSeconds -Value ([DateTime]::UtcNow.AddSeconds(20).ToString('r')) | Should -BeGreaterThan 10
    }

    Context 'Invoke-FeedFetchWithRetry (Invoke-FeedRequest mocked)' {
        BeforeEach {
            $script:Sleeps = [System.Collections.Generic.List[int]]::new()
            $script:Calls = [System.Collections.Generic.List[hashtable]]::new()
        }

        It 'does not retry permanent errors' {
            Mock -ModuleName FeedHelpers Invoke-FeedRequest {
                [PSCustomObject]@{ StatusCode = 404; Headers = @{}; Bytes = $null; Error = ''; ErrorKind = ''; FinalUrl = $Url }
            }
            $r = Invoke-FeedFetchWithRetry -Url 'https://x.example/feed' -UserAgents @('a', 'b') -MaxRetries 3 -SleepAction { param($ms) $script:Sleeps.Add($ms) }
            $r.Success | Should -BeFalse
            $r.Requests | Should -Be 1
            $r.Error | Should -Be 'HTTP 404'
            $script:Sleeps.Count | Should -Be 0
        }

        It 'rotates user agents on 403 without consuming retries, then gives up' {
            Mock -ModuleName FeedHelpers Invoke-FeedRequest {
                $script:Calls.Add($Headers)
                [PSCustomObject]@{ StatusCode = 403; Headers = @{}; Bytes = $null; Error = ''; ErrorKind = ''; FinalUrl = $Url }
            }
            $r = Invoke-FeedFetchWithRetry -Url 'https://x.example/feed' -UserAgents @('ua1', 'ua2', 'ua3') -MaxRetries 3 -SleepAction { param($ms) $script:Sleeps.Add($ms) }
            $r.Success | Should -BeFalse
            $r.Requests | Should -Be 3
            @($script:Calls | ForEach-Object { $_['User-Agent'] }) | Should -Be @('ua1', 'ua2', 'ua3')
            $r.Error | Should -Match 'blocked for all 3'
        }

        It 'succeeds after a UA rotation and keeps the bytes' {
            $script:N = 0
            Mock -ModuleName FeedHelpers Invoke-FeedRequest {
                $script:N++
                if ($script:N -eq 1) { return [PSCustomObject]@{ StatusCode = 403; Headers = @{}; Bytes = $null; Error = ''; ErrorKind = ''; FinalUrl = $Url } }
                [PSCustomObject]@{ StatusCode = 200; Headers = @{ 'ETag' = '"e1"' }; Bytes = [byte[]](1, 2, 3); Error = ''; ErrorKind = ''; FinalUrl = $Url }
            }
            $r = Invoke-FeedFetchWithRetry -Url 'https://x.example/feed' -UserAgents @('ua1', 'ua2') -MaxRetries 1 -SleepAction { param($ms) $script:Sleeps.Add($ms) }
            $r.Success | Should -BeTrue
            $r.Bytes.Length | Should -Be 3
            (Get-WebResponseHeader -Response $r.Headers -Name 'etag') | Should -Be '"e1"'
        }

        It 'backs off exponentially on 5xx and stops at MaxRetries' {
            Mock -ModuleName FeedHelpers Invoke-FeedRequest {
                [PSCustomObject]@{ StatusCode = 503; Headers = @{}; Bytes = $null; Error = ''; ErrorKind = ''; FinalUrl = $Url }
            }
            $r = Invoke-FeedFetchWithRetry -Url 'https://x.example/feed' -UserAgents @('ua1', 'ua2') -MaxRetries 3 -RetryBaseSeconds 1 -SleepAction { param($ms) $script:Sleeps.Add($ms) }
            $r.Requests | Should -Be 3
            $script:Sleeps.Count | Should -Be 2
            $script:Sleeps[0] | Should -BeGreaterOrEqual 1000
            $script:Sleeps[1] | Should -BeGreaterOrEqual 2000
        }

        It 'honours Retry-After on 429 and grants two extra attempts' {
            Mock -ModuleName FeedHelpers Invoke-FeedRequest {
                [PSCustomObject]@{ StatusCode = 429; Headers = @{ 'Retry-After' = '3' }; Bytes = $null; Error = ''; ErrorKind = ''; FinalUrl = $Url }
            }
            $r = Invoke-FeedFetchWithRetry -Url 'https://x.example/feed' -UserAgents @('ua1') -MaxRetries 2 -SleepAction { param($ms) $script:Sleeps.Add($ms) }
            $r.Requests | Should -Be 4
            $script:Sleeps | Should -Be @(3000, 3000, 3000)
            $r.Error | Should -Match '429'
        }

        It 'sends conditional headers and reports 304 as unchanged' {
            Mock -ModuleName FeedHelpers Invoke-FeedRequest {
                $script:Calls.Add($Headers)
                [PSCustomObject]@{ StatusCode = 304; Headers = @{}; Bytes = $null; Error = ''; ErrorKind = ''; FinalUrl = $Url }
            }
            $cache = @{ Etag = '"abc"'; LastModified = 'Wed, 05 Aug 2026 16:30:00 GMT' }
            $r = Invoke-FeedFetchWithRetry -Url 'https://x.example/feed' -FeedCache $cache -SleepAction { param($ms) $script:Sleeps.Add($ms) }
            $r.Success | Should -BeTrue
            $r.Unchanged | Should -BeTrue
            $script:Calls[0]['If-None-Match'] | Should -Be '"abc"'
            $script:Calls[0]['If-Modified-Since'] | Should -Be 'Wed, 05 Aug 2026 16:30:00 GMT'
        }

        It 'does not retry DNS failures' {
            Mock -ModuleName FeedHelpers Invoke-FeedRequest {
                [PSCustomObject]@{ StatusCode = 0; Headers = @{}; Bytes = $null; Error = 'No such host is known'; ErrorKind = 'dns'; FinalUrl = $Url }
            }
            $r = Invoke-FeedFetchWithRetry -Url 'https://x.example/feed' -MaxRetries 3 -SleepAction { param($ms) $script:Sleeps.Add($ms) }
            $r.Requests | Should -Be 1
            $r.Error | Should -Match 'No such host'
        }
    }
}

Describe 'Get-WebResponseHeader' {
    It 'reads headers case-insensitively from dictionaries and WebHeaderCollection' {
        $response = [PSCustomObject]@{ Headers = @{ 'ETag' = '"abc123"'; 'Last-Modified' = 'Wed, 05 Aug 2026 16:30:00 GMT' } }
        Get-WebResponseHeader -Response $response -Name 'etag' | Should -Be '"abc123"'
        Get-WebResponseHeader -Response $response -Name 'X-Missing' | Should -BeNullOrEmpty
        $bare = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
        $bare['Retry-After'] = '5'
        Get-WebResponseHeader -Response $bare -Name 'retry-after' | Should -Be '5'
        $headers = [System.Net.WebHeaderCollection]::new()
        $headers.Add('Retry-After', '5')
        Get-WebResponseHeader -Response ([PSCustomObject]@{ Headers = $headers }) -Name 'Retry-After' | Should -Be '5'
    }
}

Describe 'Configuration' {
    It 'fills missing settings with defaults' {
        $cfg = @{ Keywords = @('x'); MitreKeywords = @{}; Feeds = @('https://a'); UserAgents = @('ua'); AllowedUrlPatterns = @('^https?://') } | ConvertTo-Json | ConvertFrom-Json
        $result = Merge-ConfigDefaults -Config $cfg
        $result.Settings.ThrottleLimit | Should -Be 10
        $result.Settings.MaxResponseBytes | Should -Be 20971520
        $result.Settings.KevEnabled | Should -BeTrue
        $result.SchemaVersion | Should -Be 2
    }

    It 'normalizes string and object feed definitions and drops duplicates' {
        $cfg = @{ Feeds = @('https://www.example.com/feed', @{ Url = 'https://a.example/rss'; Name = 'A Labs'; Category = 'Vendor Research' }, 'https://www.example.com/feed') } | ConvertTo-Json -Depth 4 | ConvertFrom-Json
        $defs = @(Get-FeedDefinitions -Config $cfg -WarningAction SilentlyContinue)
        $defs.Count | Should -Be 2
        $defs[0].Name | Should -Be 'example.com'
        $defs[0].Category | Should -Be 'General'
        $defs[1].Name | Should -Be 'A Labs'
    }

    It 'accepts a valid configuration' {
        $cfg = @{
            SchemaVersion = 2
            Settings = @{ ThrottleLimit = 4; MaxRetries = 2 }
            Keywords = @('k')
            MitreKeywords = @{ T1566 = @{ Name = 'Phishing'; Keywords = @('phish') } }
            Feeds = @('https://a.example/feed', @{ Url = 'https://b.example/feed'; Name = 'B' })
            UserAgents = @('ua')
            AllowedUrlPatterns = @('^https?://')
        } | ConvertTo-Json -Depth 5 | ConvertFrom-Json
        $cfg = Merge-ConfigDefaults -Config $cfg
        Test-Configuration -Config $cfg | Should -BeTrue
    }

    It 'rejects bad feeds, bad MITRE ids and non-https webhooks' {
        $base = @{ Settings = @{}; Keywords = @('k'); MitreKeywords = @{}; Feeds = @('https://a.example/feed'); UserAgents = @('ua'); AllowedUrlPatterns = @('^https?://') }

        $c1 = $base.Clone(); $c1.Feeds = @()
        { Test-Configuration -Config (Merge-ConfigDefaults -Config ($c1 | ConvertTo-Json -Depth 5 | ConvertFrom-Json)) } | Should -Throw

        $c2 = $base.Clone(); $c2.Feeds = @(@{ Name = 'no url' })
        { Test-Configuration -Config (Merge-ConfigDefaults -Config ($c2 | ConvertTo-Json -Depth 5 | ConvertFrom-Json)) } | Should -Throw

        $c3 = $base.Clone(); $c3.MitreKeywords = @{ 'NOTATECHNIQUE' = @{ Name = 'x'; Keywords = @('y') } }
        { Test-Configuration -Config (Merge-ConfigDefaults -Config ($c3 | ConvertTo-Json -Depth 5 | ConvertFrom-Json)) } | Should -Throw

        $c4 = $base.Clone(); $c4.MitreKeywords = @{ T1566 = @{ Name = 'Phishing'; Keywords = @() } }
        { Test-Configuration -Config (Merge-ConfigDefaults -Config ($c4 | ConvertTo-Json -Depth 5 | ConvertFrom-Json)) } | Should -Throw

        $c5 = $base.Clone(); $c5.Settings = @{ WebhookEnabled = $true; WebhookUrl = 'http://hooks.example/x' }
        { Test-Configuration -Config (Merge-ConfigDefaults -Config ($c5 | ConvertTo-Json -Depth 5 | ConvertFrom-Json)) } | Should -Throw
    }

    It 'lets environment variables override the NVD key and webhook URL' {
        $tmp = New-TempPath 'tr_cfg_'
        try {
            @{
                Settings = @{ NvdApiKey = 'from-file' }; Keywords = @('k'); MitreKeywords = @{}
                Feeds = @('https://a.example/feed'); UserAgents = @('ua'); AllowedUrlPatterns = @('^https?://')
            } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmp -Encoding UTF8
            $env:THREATRAVEN_NVD_API_KEY = 'from-env'
            $env:THREATRAVEN_WEBHOOK_URL = 'https://hooks.example/y'
            $cfg = Initialize-Configuration -Path $tmp
            $cfg.Settings.NvdApiKey | Should -Be 'from-env'
            $cfg.Settings.WebhookUrl | Should -Be 'https://hooks.example/y'
        }
        finally {
            Remove-Item Env:\THREATRAVEN_NVD_API_KEY -ErrorAction SilentlyContinue
            Remove-Item Env:\THREATRAVEN_WEBHOOK_URL -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }

    It 'redacts NvdApiKey and WebhookUrl in the run-config snapshot' {
        $tmp = New-TempPath 'tr_runcfg_'
        try {
            $cfg = @{
                SchemaVersion = 2
                Settings = @{ NvdApiKey = 'super-secret'; WebhookUrl = 'https://hooks.example/x'; LogLevel = 'Info'; ThrottleLimit = 10 }
                Keywords = @('k'); MitreKeywords = @{ T1566 = @{ Name = 'Phishing'; Keywords = @('phish') } }
                Feeds = @('https://a.example/feed')
            } | ConvertTo-Json -Depth 5 | ConvertFrom-Json
            Save-RunConfiguration -Config $cfg -Path $tmp -StatePath 'state.json'
            $saved = Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json
            $saved.Settings.NvdApiKey | Should -Be '***REDACTED***'
            $saved.Settings.WebhookUrl | Should -Be '***REDACTED***'
            (Get-Content -LiteralPath $tmp -Raw) | Should -Not -Match 'super-secret'
        }
        finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Feed health status' {
    It 'keeps the legacy rules when no run history is supplied' {
        Get-FeedStatusLabel -SuccessCount 0 -FailureCount 1 | Should -Be 'unhealthy'
        Get-FeedStatusLabel -SuccessCount 1 -FailureCount 3 | Should -Be 'degraded'
        Get-FeedStatusLabel -SuccessCount 1 -FailureCount 0 | Should -Be 'healthy'
        Get-FeedStatusLabel -SuccessCount 0 -FailureCount 0 | Should -Be 'healthy'
    }

    It 'uses run history: first failure is degraded, repeated failures unhealthy, flaky success degraded' {
        Get-FeedStatusLabel -SuccessCount 0 -FailureCount 1 -RecentRuns 5 -RecentFailures 1 | Should -Be 'degraded'
        Get-FeedStatusLabel -SuccessCount 0 -FailureCount 1 -RecentRuns 5 -RecentFailures 3 | Should -Be 'unhealthy'
        Get-FeedStatusLabel -SuccessCount 1 -FailureCount 0 -RecentRuns 5 -RecentFailures 2 | Should -Be 'degraded'
        Get-FeedStatusLabel -SuccessCount 1 -FailureCount 0 -RecentRuns 5 -RecentFailures 0 | Should -Be 'healthy'
    }

    It 'Update-FeedRunHistory keeps a bounded window and counts failures' {
        $state = [PSCustomObject]@{ FeedHistory = @{} }
        1..12 | ForEach-Object { $null = Update-FeedRunHistory -State $state -FeedUrl 'https://x/feed' -Success ($_ % 3 -ne 0) }
        @($state.FeedHistory['https://x/feed']).Count | Should -Be 10
        $h = Update-FeedRunHistory -State $state -FeedUrl 'https://x/feed' -Success $false
        $h.RecentRuns | Should -Be 5
        $h.RecentFailures | Should -BeGreaterOrEqual 2
    }
}

Describe 'Persistent state' {
    It 'round-trips items, feed history and enrichment caches' {
        $tmp = New-TempPath 'tr_state_'
        try {
            $state = Initialize-ThreatRavenState -Path $tmp
            $state.Items['https://a.example/1'] = [PSCustomObject]@{
                Normalized = 'https://a.example/1'; Date = (Get-Date).ToString('o'); Source = 'https://a.example/feed'
                Title = 'Test'; Keywords = 'Malware'; MitreTechniques = ''; Cves = 'CVE-2026-0001'; Link = 'https://a.example/1'
                FirstSeen = (Get-Date).ToString('o'); LastSeen = (Get-Date).ToString('o')
            }
            $null = Update-FeedRunHistory -State $state -FeedUrl 'https://a.example/feed' -Success $true
            $state.KevCache = [PSCustomObject]@{ FetchedAt = (Get-Date).ToString('o'); Count = 1; Items = [PSCustomObject]@{ 'CVE-2026-0001' = [PSCustomObject]@{ DateAdded = '2026-01-01'; Ransomware = $true } } }
            Save-ThreatRavenState -State $state -Path $tmp

            $loaded = Initialize-ThreatRavenState -Path $tmp
            $loaded.Items.Count | Should -Be 1
            $loaded.Items['https://a.example/1'].Cves | Should -Be 'CVE-2026-0001'
            @($loaded.FeedHistory['https://a.example/feed']).Count | Should -Be 1
            $loaded.KevCache.Items.'CVE-2026-0001'.Ransomware | Should -BeTrue
        }
        finally { Remove-Item -LiteralPath $tmp, "$tmp.bak", "$tmp.tmp" -Force -ErrorAction SilentlyContinue }
    }

    It 'saves atomically and keeps a .bak of the previous state' {
        $tmp = New-TempPath 'tr_state_'
        try {
            $state = Initialize-ThreatRavenState -Path $tmp
            Save-ThreatRavenState -State $state -Path $tmp
            Test-Path -LiteralPath "$tmp.tmp" | Should -BeFalse
            $state.Items['https://a.example/1'] = [PSCustomObject]@{ Normalized = 'https://a.example/1'; Date = (Get-Date).ToString('o'); Link = 'https://a.example/1'; LastSeen = (Get-Date).ToString('o') }
            Save-ThreatRavenState -State $state -Path $tmp
            Test-Path -LiteralPath "$tmp.bak" | Should -BeTrue
            (Initialize-ThreatRavenState -Path $tmp).Items.Count | Should -Be 1
        }
        finally { Remove-Item -LiteralPath $tmp, "$tmp.tmp", "$tmp.bak" -Force -ErrorAction SilentlyContinue }
    }

    It 'preserves a corrupt state file and recovers from the .bak instead of overwriting it' {
        $tmp = New-TempPath 'tr_state_'
        try {
            $state = Initialize-ThreatRavenState -Path $tmp
            $state.Items['https://a.example/1'] = [PSCustomObject]@{ Normalized = 'https://a.example/1'; Link = 'https://a.example/1'; LastSeen = (Get-Date).ToString('o') }
            Save-ThreatRavenState -State $state -Path $tmp
            $state.Items['https://a.example/2'] = [PSCustomObject]@{ Normalized = 'https://a.example/2'; Link = 'https://a.example/2'; LastSeen = (Get-Date).ToString('o') }
            Save-ThreatRavenState -State $state -Path $tmp          # .bak now holds the 1-item state
            Set-Content -LiteralPath $tmp -Value '{ definitely not json' -Encoding UTF8

            $recovered = Initialize-ThreatRavenState -Path $tmp -WarningAction SilentlyContinue
            $recovered.Items.Count | Should -Be 1
            (Get-Content -LiteralPath "$tmp.bak" -Raw) | Should -Match 'a.example/1'
            @(Get-ChildItem -Path (Split-Path $tmp) -Filter ((Split-Path -Leaf $tmp) + '.corrupt-*')).Count | Should -Be 1
        }
        finally { Get-ChildItem -Path (Split-Path $tmp) -Filter ((Split-Path -Leaf $tmp) + '*') | Remove-Item -Force -ErrorAction SilentlyContinue }
    }

    It 'prunes by retention and cap' {
        $tmp = New-TempPath 'tr_state_'
        try {
            $state = Initialize-ThreatRavenState -Path $tmp
            $state.Items['old'] = [PSCustomObject]@{ Link = 'https://a/old'; LastSeen = (Get-Date).AddDays(-200).ToString('o') }
            1..5 | ForEach-Object { $state.Items["n$_"] = [PSCustomObject]@{ Link = "https://a/$_"; LastSeen = (Get-Date).AddMinutes(-$_).ToString('o') } }
            Save-ThreatRavenState -State $state -Path $tmp -RetentionDays 90 -MaxEntries 3
            $state.Items.ContainsKey('old') | Should -BeFalse
            $state.Items.Count | Should -Be 3
            $state.Items.ContainsKey('n1') | Should -BeTrue
        }
        finally { Remove-Item -LiteralPath $tmp, "$tmp.tmp", "$tmp.bak" -Force -ErrorAction SilentlyContinue }
    }

    It 'returns only history items within the requested window' {
        $state = [PSCustomObject]@{
            Items = @{
                'https://a.example/recent' = [PSCustomObject]@{ Normalized = 'https://a.example/recent'; Date = (Get-Date).ToString('o'); Link = 'https://a.example/recent' }
                'https://a.example/old'    = [PSCustomObject]@{ Normalized = 'https://a.example/old'; Date = (Get-Date).AddDays(-30).ToString('o'); Link = 'https://a.example/old' }
            }
        }
        $history = @(Get-ThreatRavenHistoryItems -State $state -Days 7)
        $history.Count | Should -Be 1
        $history[0].Link | Should -Be 'https://a.example/recent'
    }
}

Describe 'CVE enrichment parsing (network mocked)' {
    It 'maps CVSS 4.0 before 3.1 and keeps UNKNOWN when no metrics exist' {
        Mock -ModuleName FeedHelpers Invoke-RestMethod {
            [PSCustomObject]@{
                totalResults = 2; resultsPerPage = 2
                vulnerabilities = @(
                    [PSCustomObject]@{ cve = [PSCustomObject]@{ id = 'CVE-2026-0001'; published = '2026-09-01T00:00:00.000'; descriptions = @([PSCustomObject]@{ lang = 'en'; value = 'RCE in Foo' })
                        metrics = [PSCustomObject]@{ cvssMetricV40 = @([PSCustomObject]@{ cvssData = [PSCustomObject]@{ baseScore = 9.3; baseSeverity = 'CRITICAL' } }); cvssMetricV31 = @([PSCustomObject]@{ cvssData = [PSCustomObject]@{ baseScore = 7.5; baseSeverity = 'HIGH' } }) } } },
                    [PSCustomObject]@{ cve = [PSCustomObject]@{ id = 'CVE-2026-0002'; published = '2026-09-02T00:00:00.000'; descriptions = @([PSCustomObject]@{ lang = 'en'; value = 'Awaiting analysis' }) } }
                )
            }
        }
        $r = Get-NvdCves -Days 7 -MaxResults 100
        @($r.Cves).Count | Should -Be 2
        $r.Cves[0].severity | Should -Be 'CRITICAL'
        $r.Cves[0].score | Should -Be 9.3
        $r.Cves[0].cvss | Should -Be '4.0'
        $r.Cves[1].severity | Should -Be 'UNKNOWN'
    }

    It 'parses the KEV catalog and caches it in state' {
        Mock -ModuleName FeedHelpers Invoke-FeedRequest {
            $json = '{"vulnerabilities":[{"cveID":"cve-2024-3400","dateAdded":"2024-04-12","knownRansomwareCampaignUse":"Known","vendorProject":"PAN","product":"PAN-OS"}]}'
            [PSCustomObject]@{ StatusCode = 200; Headers = @{}; Bytes = [System.Text.Encoding]::UTF8.GetBytes($json); Error = ''; ErrorKind = ''; FinalUrl = $Url }
        }
        $state = [PSCustomObject]@{ KevCache = $null }
        $kev = Get-CisaKev -State $state
        $kev.Count | Should -Be 1
        $kev['CVE-2024-3400'].Ransomware | Should -BeTrue
        $state.KevCache.Count | Should -Be 1
        # second call served from cache: no request
        $kev2 = Get-CisaKev -State $state
        $kev2.Count | Should -Be 1
        Should -Invoke -ModuleName FeedHelpers Invoke-FeedRequest -Times 1 -Exactly
    }

    It 'fetches EPSS in batches and only for uncached ids' {
        Mock -ModuleName FeedHelpers Invoke-FeedRequest {
            $ids = ([uri]$Url).Query -replace '^\?cve=', '' -split ','
            $data = @($ids | ForEach-Object { "{""cve"":""$_"",""epss"":""0.5"",""percentile"":""0.9""}" }) -join ','
            [PSCustomObject]@{ StatusCode = 200; Headers = @{}; Bytes = [System.Text.Encoding]::UTF8.GetBytes("{""data"":[$data]}"); Error = ''; ErrorKind = ''; FinalUrl = $Url }
        }
        $state = [PSCustomObject]@{ EpssCache = $null }
        $ids = 1..150 | ForEach-Object { 'CVE-2026-{0:D4}' -f $_ }
        $r = Get-EpssScores -CveIds $ids -State $state -BatchSize 100
        $r.Count | Should -Be 150
        $r['CVE-2026-0001'].Epss | Should -Be 0.5
        Should -Invoke -ModuleName FeedHelpers Invoke-FeedRequest -Times 2 -Exactly
        $r2 = Get-EpssScores -CveIds @('CVE-2026-0001', 'CVE-2026-9999') -State $state
        $r2.Count | Should -Be 2
        Should -Invoke -ModuleName FeedHelpers Invoke-FeedRequest -Times 3 -Exactly
    }
}
