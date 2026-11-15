# HexBrain — Cyber Intelligence Map & MCP Server

An interactive knowledge map of 15,244 disclosed HackerOne bug bounty reports across 428 programs, 215 weaknesses, and 406k+ CVEs.

Includes a complete **Model Context Protocol (MCP)** server for local AI assistant integration (Claude Code, Claude Desktop, Cursor, Windsurf, Antigravity) with **zero sign-in required**.

---

## Features

- **Exact Radial Canvas Visualizer**: Central radial chord graph with 18 vulnerability classes, weakness barcode strips, tree-root connectors, particle-pulsed bezier curves, and a rotating CVE ring.
- **3-Lens Dial System**:
  - **Vulnerabilities**: Exploit taxonomy across 18 classes and 215 weaknesses.
  - **Programs**: Honeycomb lattice of 428 target programs with asset surfaces and 1.7M+ subdomains.
  - **CVEs**: Radial timeline from 2000 to 2026 tracking 406k+ CVEs and CISA KEV (in-the-wild) constellations.
- **Interactive Command Palette (`Find [F]`)**: Instant keyboard-driven search modal across reports, weaknesses, and targets.
- **Deep Report Reader**: Detailed write-ups, reproduction steps, impact assessments, and bounty payouts.
- **Direct MCP Server**: Ready-to-use HTTP and stdio Model Context Protocol server exposing 8 security intelligence tools with no authentication barriers.

---

## Architecture

```
hexbrain/
├── server.py              # Main backend server (HTTP API + MCP HTTP endpoint)
├── mcp_server.py          # Core Model Context Protocol engine & tool handlers
├── mcp_stdio.py           # Standard I/O MCP transport for Claude Desktop / Cursor
├── db.py                  # SQLite schema & database connection layer
├── seed_data.py           # Seeding engine for reports, CVEs, bypasses, payloads
├── hexbrain.db            # Persistent SQLite database
├── index.html             # Main radial visualization page
├── _next/                 # Static chunks, fonts, and stylesheets
├── pages_data/            # Subpage templates (/browse, /bypasses, /payloads, /cves, /about)
└── logos/                 # Program asset logos
```

---

## Quick Start

### 1. Run the Server
```bash
python3 server.py 8080
```
Open **`http://localhost:8080`** in any modern web browser.

---

## Model Context Protocol (MCP) Integration

HexBrain provides open, direct MCP access without requiring Google sign-in or API keys.

### Claude Code
```bash
claude mcp add --transport http hexbrain http://localhost:8080/api/mcp
```

### Claude Desktop / Cursor / Antigravity (`claude_desktop_config.json`)

**Via stdio:**
```json
{
  "mcpServers": {
    "hexbrain": {
      "command": "python3",
      "args": ["/path/to/hexbrain/mcp_stdio.py"]
    }
  }
}
```

**Via HTTP:**
```json
{
  "mcpServers": {
    "hexbrain": {
      "url": "http://localhost:8080/api/mcp"
    }
  }
}
```

---

## Available MCP Tools

| Tool | Parameters | Description |
|---|---|---|
| `search_reports` | `query`, `vulnerability_class`, `program`, `weakness`, `severity`, `limit` | Search 15k+ HackerOne disclosed reports with bounty amounts, upvotes, and findings. |
| `get_report` | `report_id` | Fetch full technical write-up, reproduction steps, and impact for a specific report. |
| `list_classes` | *none* | List all 18 core vulnerability classes with report counts and historical bounties. |
| `list_weaknesses` | `vulnerability_class` | List specific weaknesses, tags, and report frequencies. |
| `list_programs` | `query`, `min_reports`, `limit` | List bug bounty targets, report totals, and mapped attack surface subdomains. |
| `search_payloads` | `query`, `category`, `limit` | Query exploit payloads (XSS, SQLi, SSRF, SSTI, Command Injection, LFI/RFI, XXE). |
| `search_bypasses` | `query`, `protection_type`, `limit` | Search real-world filter, WAF, 2FA/MFA race condition, and rate limit bypasses. |
| `search_cves` | `query`, `exploited_in_wild`, `min_cvss`, `limit` | Search CVE database with EPSS likelihood scores and CISA KEV status. |
| `sync_live_sources` | `sources` | Lively capture & ingest fresh intelligence from external feeds (CISA KEV, GitHub Advisories, Target scopes). |
| `get_data_sources_status` | *none* | View live status, record counts, and last synchronization timestamps across all connected security feeds. |

---

## Live Data Sources & Continuous Ingestion

HexBrain automatically connects to and ingests real-time threat intelligence from 5 external feeds:

1. **CISA KEV (Known Exploited Vulnerabilities)**: Live catalog of active zero-days and exploited-in-the-wild vulnerabilities.
2. **GitHub Security Advisory Database**: Real-time CVEs, GHSA ecosystem advisories, and severity ratings.
3. **FIRST EPSS (Exploit Prediction Scoring System)**: Daily predictive probability scores forecasting 30-day exploit likelihood.
4. **HackerOne & Bugcrowd Attack Surfaces**: Live tracking of 500+ programs and 1.6k+ in-scope subdomains.
5. **Community Exploit Payloads & Bypasses**: Curated PayloadsAllTheThings vectors and disclosed writeups.

To trigger an on-demand sync from the command line:
```bash
python3 sync_manager.py
```
Or via HTTP:
```bash
curl -X POST http://localhost:8080/api/sync
```
Or directly from your AI assistant using the `sync_live_sources` MCP tool!

---

## License

MIT License. Educational and authorized security research use only.
