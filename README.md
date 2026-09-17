# ThreatRaven

APT Intelligence Feed Monitor - fetches, matches, enriches and reports on threat intelligence from 110+ cybersecurity RSS/Atom feeds, CISA KEV, FIRST EPSS and NVD.

![ThreatRaven Dashboard](assets/screenshot.png)

## What it does

ThreatRaven monitors RSS/Atom feeds from security vendors, research labs, CERTs, vendor PSIRTs, disclosure lists and news sites. It matches incoming articles against configurable keywords and MITRE ATT&CK techniques, extracts CVE identifiers, flags anything that references a CISA Known Exploited Vulnerability, attaches EPSS exploit-probability scores, and generates an interactive HTML dashboard and a CSV export.

**Core capabilities (v5.0):**

- 110+ curated feeds grouped by category (Vendor Research, Cloud Security, ICS/OT, Government/CERT, Vendor Advisory, Exploit/Disclosure, Ransomware, News, Community), every one verified live at release time
- `HttpClient`-based fetching: gzip/deflate on Windows PowerShell 5.1, a hard response-size cap, streaming reads, identical behaviour on PowerShell 5.1 and 7+
- Bounded retry budget per feed: exponential backoff on 5xx/timeouts, `Retry-After`-aware 429 handling, user-agent rotation only on 403/406, no retries for DNS/TLS/oversize failures
- Per-host request gate enforced across all workers (configurable per domain, e.g. reddit.com), plus a global deadline
- Regexes compiled once and shared with workers; deduplication before matching; results processed as feeds complete
- CVE extraction from article text, CISA KEV and FIRST EPSS enrichment for both articles and the NVD table, CVSS 4.0/3.x/2.0
- MITRE ATT&CK matching by curated keywords (configurable minimum distinct hits per technique) plus explicit `T1234.001` references in the text
- All timestamps normalised to UTC; the report shows local time and states the offset
- Persistent state (`ThreatRavenState.json`): cross-run deduplication, ETag/Last-Modified conditional requests, per-feed run history, NVD/KEV/EPSS caches. Atomic saves with a `.bak`; a corrupt file is preserved as `.corrupt-<timestamp>` and the backup is loaded
- Feed health with a status derived from the last five runs (healthy / degraded / unhealthy), not just the current one
- Self-contained HTML report: Chart.js and the logo are inlined; data is embedded as JSON and rendered with DOM APIs under a strict nonce CSP (no inline handlers, no `innerHTML` with data, no network access)
- Structured JSON-lines logging with retention-based rotation, console verbosity controlled by `LogLevel`
- HTTPS-only webhook notifications (Slack/Teams-compatible)
- Secrets via environment variables: `THREATRAVEN_NVD_API_KEY`, `THREATRAVEN_WEBHOOK_URL`
- PowerShell 5.1+ compatible, no external modules required

## Quick start

```powershell
.\ThreatRaven.ps1
```

First run treats everything as new; subsequent runs deduplicate automatically and include the last 7 days of previously-seen items as "seen" entries.

## Parameters

| Parameter | Description |
|---|---|
| `-ConfigPath` | Path to custom `config.json` (default: script directory) |
| `-PreviousCsvPath` | Previous CSV to seed deduplication (backward compatibility) |
| `-SkipDeduplication` | Ignore state/previous CSV; treat everything as new this run |
| `-StatePath` | Persistent state file (default: `ThreatRavenState.json`) |
| `-LogDir` | Log directory (default: `logs`) |
| `-OutputDir` | Output directory (default: script directory) |
| `-ExportHealthReport` | Export feed health to JSON |
| `-NonInteractive` | Kept for compatibility; the script has no prompts |
| `-NoOpenReport` | Don't auto-open the HTML report |
| `-QuietMode` | Suppress ALL console output (logs still written) |

## Examples

```powershell
# Basic run
.\ThreatRaven.ps1

# Scheduled / CI mode - no browser, export health report
.\ThreatRaven.ps1 -NoOpenReport -ExportHealthReport -QuietMode

# Keep the NVD key out of config.json
$env:THREATRAVEN_NVD_API_KEY = '...'
.\ThreatRaven.ps1 -NoOpenReport

# Custom config and output
.\ThreatRaven.ps1 -ConfigPath "C:\Config\intel.json" -OutputDir "C:\Reports"
```

## Configuration

Edit `config.json` (or pass `-ConfigPath`). The loader validates the file, merges missing settings with defaults, applies environment overrides, and reports bad values before anything runs.

- **Keywords** - terms that decide whether an article is included
- **MitreKeywords** - technique IDs, names and detection keywords. Generic tokens (`http`, `download`, `zip`...) were removed in v5 because they tagged almost every article; add your own with care and raise `MitreMinKeywordHits` if precision matters more than recall
- **Feeds** - either a URL string or `{ "Url", "Name", "Category" }`. Names appear in the report and health panel; categories drive the report filter
- **AllowedUrlPatterns** - feed URLs must match at least one
- **UserAgents** - tried in order; rotation only happens on 403/406. The default list identifies the tool honestly and falls back to a browser UA. Spoofing crawler identities (Feedfetcher, FeedBurner) was removed
- **Settings** - see below

### Settings reference

| Setting | Default | Purpose |
|---|---|---|
| `VulnDays` | 7 | NVD lookup window in days (max 120) |
| `ThrottleLimit` | 10 | Max parallel feed workers (1-64) |
| `FeedTimeoutSeconds` | 30 | Per-request timeout |
| `MaxRetries` | 3 | Attempts per feed for retryable failures (+2 after a 429) |
| `RetryBaseDelaySeconds` | 2 | Exponential backoff base |
| `MaxResponseBytes` | 20971520 | Hard cap on a feed response (streamed, aborted when exceeded) |
| `LogLevel` | Info | Console verbosity: Debug, Info, Warning, Error (the log file always gets everything) |
| `ValidateCertificates` | true | If false, disables certificate validation for the run |
| `ExportHealthReport` | false | Also honoured via `-ExportHealthReport` |
| `NvdEnabled` | true | Fetch CVEs published in the window into the report |
| `NvdApiKey` | "" | Optional NVD API key (or `THREATRAVEN_NVD_API_KEY`) |
| `NvdMaxResults` | 2000 | Cap on CVEs embedded in the report |
| `NvdCacheHours` | 6 | NVD cache lifetime in the state file |
| `NvdKeywordFilter` | false | Only include CVEs whose description matches your keywords |
| `KevEnabled` | true | Download the CISA KEV catalog and flag matching CVEs/articles |
| `EpssEnabled` | true | Fetch EPSS scores for article and NVD CVEs |
| `EnrichmentCacheHours` | 12 | KEV/EPSS cache lifetime |
| `MitreMinKeywordHits` | 1 | Distinct keyword hits required before a technique is tagged (explicit `T1234` references always count) |
| `MinHostRequestIntervalMs` | 250 | Min spacing between requests to the same host |
| `HostRequestIntervalMsOverrides` | `{"reddit.com": 10000}` | Per-domain spacing (matches subdomains; enforced across workers, retries included) |
| `GlobalTimeoutSeconds` | 900 | Overall deadline for the fetch phase |
| `StateRetentionDays` | 90 | Prune seen links older than this |
| `StateMaxEntries` | 20000 | Cap on stored seen links |
| `ReportHistoryDays` | 7 | Include previously-seen items from this window in reports |
| `LogRetentionDays` | 14 | Delete log files older than this |
| `EnableConditionalRequests` | true | Send ETag/If-Modified-Since (validators are only stored after a feed parsed successfully) |
| `WebhookEnabled` / `WebhookUrl` | false / "" | HTTPS webhook for a run summary (or `THREATRAVEN_WEBHOOK_URL`) |

## Output

| File | Description |
|---|---|
| `APT_Report_YYYY-MM-DD_HH-mm-ss.html` | Interactive dashboard |
| `APT_Report_YYYY-MM-DD_HH-mm-ss.csv` | Data export: Date (UTC), SourceName, Category, Source, Title, Keywords, MitreTechniques, Cves, Link, IsNew |
| `RunConfig_YYYY-MM-DD_HH-mm-ss.json` | Config snapshot for this run (secrets redacted) |
| `FeedHealth_YYYY-MM-DD_HH-mm-ss.json` | Feed health export (when enabled) |
| `ThreatRavenState.json` | Persistent dedupe/cache/history state (`.bak` = last good save) |
| `logs/ThreatFeed_YYYY-MM-DD_HH-mm-ss.log` | Structured JSON-lines execution log |

## HTML report features

- Stat tiles: total, new, matching, KEV-linked, MITRE techniques, feeds, runtime
- Filters: date window, new/seen/KEV-linked/mentions-a-CVE, category, free text (titles, sources, keywords, CVE ids)
- Day navigation instead of one endless table: the report opens on the run day, other days are tabs (older ones in a dropdown), each day is paged (25/50/100/all rows). Searching spans all days; clearing the search returns to the run day
- Keyword doughnut and top-sources bars that follow the current selection (day + filters)
- Sortable table with source names, MITRE badges (click to drill down), CVE badges linking to NVD, KEV tags
- MITRE ATT&CK modal with technique links and per-technique article lists
- CVE modal: severity and KEV tiles, CVSS version, EPSS probability and percentile, sort by newest/EPSS/CVSS, text filter
- Feed health panel with category, status from run history, response time, HTTP status and last error
- Dark/light theme (persisted), print CSS, Escape closes modals
- AI analysis buttons (ChatGPT, Claude, Gemini) with a prompt that tells the assistant to treat article content as untrusted

## Development

```powershell
# Unit tests (Pester 5+; installs Pester to CurrentUser if missing)
.\Tests\Invoke-Tests.ps1

# Live smoke test with a small feed set
.\ThreatRaven.ps1 -ConfigPath .\Tests\smoke-config.json -NoOpenReport
```

The HTML/CSS/JS live in `assets/report-template.html`. The script fills `{{TOKEN}}` placeholders and embeds the report data as JSON in `<script type="application/json" id="tr-data">`. Pester covers the module helpers, the retry state machine (with mocked HTTP), state recovery, enrichment parsing (mocked network) and template regression checks. CI runs Pester on PowerShell 5.1 and 7, PSScriptAnalyzer, and a live smoke run.

Avoid `\uXXXX` escapes in PowerShell source; use `[char]0x....` so editors and tooling never decode them.

## Changelog

### v5.0 (2026-09-17)

- **Fetching:** `HttpClient` replaces `Invoke-WebRequest` (gzip on PS 5.1, hard response cap, streaming). Retry state machine with UA rotation only on 403/406, no retries on DNS/TLS/oversize, `Retry-After` honoured
- **Correctness:** UTC date normalisation (RFC1123 "GMT" dates were skewed by the local offset); ETag stored only after a successful parse; linkless items skipped instead of collapsing onto the feed URL; corrupt state preserved and recovered from `.bak`; CISA advisory ids now resolve; `LogLevel` applies to all levels; CVSS 4.0
- **Performance:** regexes compiled once and shared by reference (was ~50k IL compilations per run), dedupe before matching, module imported once per runspace, streaming result processing, redundant dispatch sleep removed
- **Enrichment:** CVE ids extracted from articles, CISA KEV and FIRST EPSS joined into articles and the NVD table, explicit ATT&CK ids matched, generic MITRE keywords pruned and eight techniques added
- **Report:** JSON data block + DOM-only rendering under a stricter CSP; day tabs with pagination instead of one endless table; category and KEV filters; EPSS columns; fixed legend, sort toggle, light theme, filtered sources
- **Sources:** feeds as `{Url, Name, Category}`; 44 verified sources added, dead/redirected/bot-blocked ones removed; spoofed crawler user agents dropped
- **Security:** attribute-injection paths closed, HTTPS-only webhook without local paths, env-var secrets, CSPRNG nonce, self-deleting lock file
- **Tooling:** Pester 5 test suite with mocked HTTP; CI pins Pester, runs the analyzer and validates the smoke report

### v4.1 / v4.0

Stored-XSS fix, state-based dedupe, server-side NVD, CSP-nonce reports, atomic state saves, rate-limit gate. See git history for details.

## Requirements

- PowerShell 5.1+ (Windows PowerShell or PowerShell 7)
- No external modules required at runtime
- Internet access for feeds, NVD, CISA KEV and FIRST EPSS

## Project structure

```
ThreatRaven/
|-- ThreatRaven.ps1             # Main entry point (pipeline)
|-- FeedHelpers.psm1            # HTTP, parsing, config, state, enrichment, webhook helpers
|-- config.json                 # Keywords, MITRE techniques, feeds, settings
|-- assets/
|   |-- logo.png
|   |-- screenshot.png
|   '-- report-template.html    # HTML/JS/CSS report template
|-- lib/
|   '-- chart.min.js            # Chart.js (inlined into reports at generation)
|-- Tests/                      # Pester tests + smoke configs
|-- .github/workflows/ci.yml    # Pester + PSScriptAnalyzer + smoke CI
|-- logs/                       # Created at runtime
'-- ThreatRavenState.json       # Created at runtime
```

## License

MIT - see [LICENSE](LICENSE).

## Author

**Diyar Abbas**
