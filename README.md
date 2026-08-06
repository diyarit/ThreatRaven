# ThreatRaven

APT Intelligence Feed Monitor - fetches, matches, and reports on threat intelligence from 76+ cybersecurity RSS feeds.

![ThreatRaven Dashboard](assets/screenshot.png)

## What it does

ThreatRaven monitors RSS/Atom feeds from security vendors, research labs, and threat intel sources. It matches incoming articles against configurable keywords and MITRE ATT&CK techniques, then generates an interactive HTML dashboard and CSV export.

**Core capabilities (v4):**

- Parallel feed fetching with retry logic, per-host pacing, and a global deadline
- Rate-limit aware: honors `Retry-After` headers with extra backoff attempts for 429s
- Clear feed error reporting, including detection of HTML pages served in place of RSS/Atom
- ETag / Last-Modified conditional requests - unchanged feeds skip re-processing (bandwidth-friendly)
- Persistent state file (`ThreatRavenState.json`) - automatic deduplication across runs, feed health history, and NVD caching (no more manual previous-CSV prompts)
- Keyword and MITRE ATT&CK technique matching with pre-compiled regexes
- Interactive HTML report with charts, sorting, filtering, dark/light theme, CSP nonce, and DOM-based rendering (no inline-JS string injection)
- Server-side NVD CVE lookup (paginated, rate-limit aware, optional API key, cached)
- Feed health monitoring with per-feed response times and failure tracking
- Structured JSON-lines logging with retention-based rotation
- Webhook notifications (Slack/Teams-compatible)
- CSV export for SIEM integration or further analysis
- PowerShell 5.1+ compatible, no external modules required

## Quick start

```powershell
.\ThreatRaven.ps1
```

That's it. First run treats everything as new; subsequent runs deduplicate automatically and include the last 7 days of previously-seen items as "seen" entries.

## Parameters

| Parameter | Description |
|---|---|
| `-ConfigPath` | Path to custom `config.json` (default: script directory) |
| `-PreviousCsvPath` | Previous CSV to seed deduplication (backward compatibility) |
| `-SkipDeduplication` | Ignore state/previous CSV; treat everything as new this run |
| `-StatePath` | Persistent state file (default: `ThreatRavenState.json`) |
| `-OutputDir` | Output directory (default: script directory) |
| `-ExportHealthReport` | Export feed health to JSON |
| `-NonInteractive` | No prompts (v4 has no prompts; kept for compatibility) |
| `-NoOpenReport` | Don't auto-open HTML report |
| `-QuietMode` | Suppress ALL console output (logs still written) |

## Examples

```powershell
# Basic run
.\ThreatRaven.ps1

# CI/CD mode - no prompts, no browser, export health report
.\ThreatRaven.ps1 -NonInteractive -NoOpenReport -ExportHealthReport

# Seed dedupe from an older CSV once, then let the state file take over
.\ThreatRaven.ps1 -PreviousCsvPath ".\reports\last_run.csv"

# Custom config and output
.\ThreatRaven.ps1 -ConfigPath "C:\Config\intel.json" -OutputDir "C:\Reports"
```

## Configuration

Edit `config.json` (or pass `-ConfigPath`). The loader validates the file, merges missing settings with defaults, and reports bad values before anything runs.

- **Keywords** - terms to match in article titles/descriptions
- **MITRE ATT&CK** - technique IDs, names, and detection keywords
- **Feeds** - RSS/Atom URLs to monitor (validated against `AllowedUrlPatterns`)
- **Settings** - see below

### Settings reference

| Setting | Default | Purpose |
|---|---|---|
| `VulnDays` | 7 | NVD lookup window in days |
| `ThrottleLimit` | 10 | Max parallel feed workers |
| `FeedTimeoutSeconds` | 25 | Per-request HTTP timeout |
| `MaxRetries` | 3 | Retry count per feed (permanent 4xx errors are not retried) |
| `RetryBaseDelaySeconds` | 2 | Exponential backoff base |
| `LogLevel` | Info | Console verbosity (`Debug` writes more) |
| `ValidateCertificates` | true | If false, disables certificate validation for the run |
| `ExportHealthReport` | false | Also honor via `-ExportHealthReport` switch |
| `NvdEnabled` | true | Fetch CVEs server-side into the report |
| `NvdApiKey` | "" | Optional NVD API key (50 req/30s vs 5 req/30s) |
| `NvdMaxResults` | 2000 | Cap on CVEs embedded in the report |
| `NvdCacheHours` | 6 | How long NVD results are cached in the state file |
| `NvdKeywordFilter` | false | Only include CVEs whose description matches your keywords |
| `MinHostRequestIntervalMs` | 250 | Min spacing between requests to the same host |
| `GlobalTimeoutSeconds` | 900 | Overall deadline for all feeds |
| `StateRetentionDays` | 90 | Prune seen links older than this |
| `StateMaxEntries` | 20000 | Cap on stored seen links |
| `ReportHistoryDays` | 7 | Include previously-seen items from this window in reports |
| `LogRetentionDays` | 14 | Delete log files older than this |
| `EnableConditionalRequests` | true | Send ETag/If-Modified-Since headers |
| `WebhookEnabled` / `WebhookUrl` | false / "" | Post a run summary to a Slack/Teams webhook |

## Output

| File | Description |
|---|---|
| `APT_Report_YYYY-MM-DD_HH-mm-ss.html` | Interactive dashboard |
| `APT_Report_YYYY-MM-DD_HH-mm-ss.csv` | Raw data export |
| `RunConfig_YYYY-MM-DD_HH-mm-ss.json` | Config snapshot for this run |
| `FeedHealth_YYYY-MM-DD_HH-mm-ss.json` | Feed health export (when enabled) |
| `ThreatRavenState.json` | Persistent dedupe/cache/health state |
| `logs/ThreatFeed_YYYY-MM-DD_HH-mm-ss.log` | Structured JSON-lines execution log |

## HTML Report Features

- Doughnut chart for keyword distribution and top-sources chart
- Sortable, searchable data table with date/status filters
- Dark/light theme toggle (persisted)
- Feed health panel with per-feed status, latency, and error details
- MITRE ATT&CK technique drill-down with article lists
- CVE report (NVD) with severity stats, chart, and search - served from embedded report data (no client-side API calls)
- AI analysis buttons (ChatGPT, Claude, Gemini)
- Content Security Policy with a per-report nonce; all content rendered via DOM APIs and all interactions bound with `addEventListener` (no inline event handlers), keeping the strict CSP fully functional
- Print-optimized CSS

## Development

```powershell
# Unit tests (Pester 3.x+)
Invoke-Pester .\Tests\FeedHelpers.Tests.ps1

# Live smoke test with a small feed set
.\ThreatRaven.ps1 -ConfigPath .\Tests\smoke-config.json -NonInteractive -NoOpenReport
```

The HTML/CSS/JS live in `assets/report-template.html` with `{{TOKEN}}` placeholders filled by the script - edit the template without touching the pipeline. Pester covers the module helpers plus a CSP regression check that fails if the template regains inline event handlers. CI runs Pester, PSScriptAnalyzer, and a live smoke run on every push.

## Requirements

- PowerShell 5.1+ (Windows PowerShell or PowerShell Core)
- No external modules required
- Internet access for feed fetching and CVE lookups

## Project structure

```
ThreatRaven/
|-- ThreatRaven.ps1             # Main entry point (pipeline)
|-- FeedHelpers.psm1            # Parsing, config, state, NVD, webhook helpers
|-- config.json                 # Keywords, MITRE techniques, feeds, settings
|-- assets/
|   |-- logo.png
|   |-- screenshot.png
|   '-- report-template.html    # HTML/JS/CSS report template ({{TOKEN}}s)
|-- lib/
|   '-- chart.min.js            # Chart.js (local, no CDN)
|-- Tests/                      # Pester tests + smoke configs
|-- .github/workflows/ci.yml    # Pester + PSScriptAnalyzer + smoke CI
|-- logs/                       # Created at runtime
'-- ThreatRavenState.json       # Created at runtime
```

## License

MIT - see [LICENSE](LICENSE).

## Author

**Diyar Abbas**
