"""
HexBrain Model Context Protocol (MCP) Server Implementation
Provides structured access to vulnerability intelligence, bug bounty reports,
exploit payloads, bypass techniques, and CVE mappings.
No Google sign-in required — direct access.
"""

import json
import sqlite3
import os
from db import get_db

SERVER_INFO = {
    "name": "hexbrain-security-intelligence",
    "version": "2.0.0",
    "description": "HexBrain Cybersecurity Knowledge Map and Bug Bounty Intelligence Server"
}

TOOLS = [
    {
        "name": "search_reports",
        "description": "Search 15,000+ publicly disclosed HackerOne bug bounty reports by keyword, vulnerability class, target program, weakness, or severity. Returns report summaries, bounties, and findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search term (e.g. 'SSRF AWS metadata', 'OAuth redirect_uri', 'SQL injection billing', 'GraphQL introspection')"
                },
                "vulnerability_class": {
                    "type": "string",
                    "description": "Filter by class (e.g. 'XSS', 'SSRF', 'SQLI', 'AUTH', 'RCE', 'IDOR', 'CSRF', 'TRAV')"
                },
                "program": {
                    "type": "string",
                    "description": "Filter by bug bounty program name (e.g. 'Shopify', 'Uber', 'GitHub', 'Slack', 'WordPress', 'Yahoo!')"
                },
                "weakness": {
                    "type": "string",
                    "description": "Filter by specific weakness name (e.g. 'Reflected XSS', 'Stored XSS', 'Blind SSRF')"
                },
                "severity": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                    "description": "Filter by minimum severity level"
                },
                "limit": {
                    "type": "integer",
                    "default": 10,
                    "description": "Maximum number of reports to return (1-50)"
                }
            }
        }
    },
    {
        "name": "get_report",
        "description": "Retrieve the full technical write-up, reproduction steps, impact, and bounty details for a specific disclosed bug bounty report by ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "report_id": {
                    "type": "integer",
                    "description": "The numeric HackerOne report ID (e.g. 105133, 97229, 629102, 846338, 482910)"
                }
            },
            "required": ["report_id"]
        }
    },
    {
        "name": "list_classes",
        "description": "List all 18 core vulnerability classes tracked in HexBrain with total report counts, weakness counts, and historical bounty payouts.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "list_weaknesses",
        "description": "List specific vulnerability weaknesses under a given class or across the entire taxonomy with report frequency and severity distributions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vulnerability_class": {
                    "type": "string",
                    "description": "Optional class ID or name (e.g. 'XSS', 'AUTH', 'RCE', 'SSRF', 'SQLI')"
                }
            }
        }
    },
    {
        "name": "list_programs",
        "description": "List bug bounty programs with their disclosed report counts, total bounty payouts, and mapped attack surface subdomains.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search program name (e.g. 'Shopify', 'GitLab', 'Uber', 'Slack', 'Coinbase')"
                },
                "min_reports": {
                    "type": "integer",
                    "default": 1,
                    "description": "Minimum number of disclosed reports"
                },
                "limit": {
                    "type": "integer",
                    "default": 20,
                    "description": "Number of programs to return"
                }
            }
        }
    },
    {
        "name": "search_payloads",
        "description": "Search exploit payloads and testing vectors (XSS, SQLi, SSRF, SSTI, Command Injection, LFI/RFI, XXE, Deserialization, etc.).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search payload technique or target (e.g. 'polyglot', 'time-based', 'metadata', 'popen', 'space bypass')"
                },
                "category": {
                    "type": "string",
                    "description": "Payload category (e.g. 'XSS', 'SQLI', 'SSRF', 'SSTI', 'CMD', 'TRAV', 'XXE')"
                },
                "limit": {
                    "type": "integer",
                    "default": 10,
                    "description": "Maximum number of payloads to return"
                }
            }
        }
    },
    {
        "name": "search_bypasses",
        "description": "Search real-world bypass techniques from disclosed reports (WAF evasion, filter bypasses, 2FA/MFA workarounds, rate limit circumvention, CSP bypasses).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search keyword (e.g. 'unicode', 'chunked', 'race condition', 'X-Forwarded-For', 'double encoding')"
                },
                "protection_type": {
                    "type": "string",
                    "description": "Protection category: 'Web application firewalls', 'Input filters and sanitisers', 'Two-factor and verification codes', 'Rate limits and lockouts', 'Content Security Policy', 'Earlier fixes'"
                },
                "limit": {
                    "type": "integer",
                    "default": 10,
                    "description": "Maximum bypass techniques to return"
                }
            }
        }
    },
    {
        "name": "search_cves",
        "description": "Search CVE database with EPSS likelihood scores, CVSS severity, affected products, and CISA Known Exploited Vulnerabilities (KEV) status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "CVE ID or product keyword (e.g. 'GitLab', 'Ivanti', 'WordPress', 'CVE-2026-116606', 'PHP')"
                },
                "exploited_in_wild": {
                    "type": "boolean",
                    "description": "Filter strictly to CISA KEV (exploited in the wild) vulnerabilities"
                },
                "min_cvss": {
                    "type": "number",
                    "description": "Minimum CVSS score (0.0 to 10.0)"
                },
                "limit": {
                    "type": "integer",
                    "default": 15,
                    "description": "Maximum number of CVEs to return"
                }
            }
        }
    },
    {
        "name": "sync_live_sources",
        "description": "Lively capture and ingest latest intelligence from external security feeds: CISA KEV, GitHub Advisory Database, HackerOne/Bugcrowd targets, and EPSS scores.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sources": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["all", "cisa_kev", "github_advisories", "hackerone_disclosures", "first_epss", "bounty_targets", "payloads_bypasses"]
                    },
                    "description": "List of sources to synchronize (default: ['all'])"
                }
            }
        }
    },
    {
        "name": "get_data_sources_status",
        "description": "Get current status, record counts, and last synchronization timestamps for all connected live security data feeds.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]

RESOURCES = [
    {
        "uri": "hexbrain://classes",
        "name": "All Vulnerability Classes",
        "mimeType": "application/json",
        "description": "Complete overview of 18 vulnerability classes and metrics"
    },
    {
        "uri": "hexbrain://stats",
        "name": "HexBrain Platform Statistics",
        "mimeType": "application/json",
        "description": "Global report, payout, program, and CVE metrics"
    },
    {
        "uri": "hexbrain://cves/ring",
        "name": "HexBrain Flagship CVE Ring",
        "mimeType": "application/json",
        "description": "High-priority tracked zero-days and critical CVEs"
    }
]

def handle_mcp_request(req):
    """
    Process incoming JSON-RPC 2.0 MCP request and return dict response.
    """
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params", {}) or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {
                        "listChanged": False
                    },
                    "resources": {
                        "subscribe": False,
                        "listChanged": False
                    }
                },
                "serverInfo": SERVER_INFO
            }
        }

    elif method == "notifications/initialized":
        return None  # Notifications do not require response

    elif method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {}
        }

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": TOOLS
            }
        }

    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        try:
            result_content = execute_tool(tool_name, arguments)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": result_content
                        }
                    ],
                    "isError": False
                }
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Error executing tool '{tool_name}': {str(e)}"
                        }
                    ],
                    "isError": True
                }
            }

    elif method == "resources/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "resources": RESOURCES
            }
        }

    elif method == "resources/read":
        uri = params.get("uri")
        conn = get_db()
        cur = conn.cursor()

        if uri == "hexbrain://classes":
            cur.execute("SELECT id, name, count, bounty, weaknesses_count FROM classes ORDER BY count DESC")
            data = [dict(row) for row in cur.fetchall()]
            conn.close()
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "contents": [{
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(data, indent=2)
                    }]
                }
            }
        elif uri == "hexbrain://stats":
            cur.execute("SELECT count(*), coalesce(sum(bounty), 0.0) FROM reports")
            rep_cnt, total_bounty = cur.fetchone()
            cur.execute("SELECT count(*) FROM programs WHERE count > 0")
            prog_cnt = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM cves")
            cve_cnt = cur.fetchone()[0]
            conn.close()
            stats = {
                "reports_indexed": rep_cnt,
                "programs": prog_cnt,
                "classes": 18,
                "cves_tracked": cve_cnt,
                "total_bounties_tracked": f"${round(total_bounty):,}",
                "total_bounty_raw": total_bounty
            }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "contents": [{
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(stats, indent=2)
                    }]
                }
            }
        conn.close()
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32602, "message": f"Unknown resource URI: {uri}"}
        }

    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method '{method}' not found"
            }
        }

def execute_tool(name, args):
    """
    Execute tool against HexBrain database and return markdown-formatted string.
    """
    conn = get_db()
    cur = conn.cursor()

    if name == "search_reports":
        q = args.get("query", "").strip()
        v_class = args.get("vulnerability_class")
        program = args.get("program")
        weakness = args.get("weakness")
        severity = args.get("severity")
        limit = min(50, max(1, args.get("limit", 10)))

        query_sql = "SELECT id, title, program, severity, weakness, class_id, bounty, votes FROM reports WHERE 1=1"
        params = []

        if q:
            query_sql += " AND (title LIKE ? OR weakness LIKE ? OR program LIKE ? OR writeup LIKE ?)"
            term = f"%{q}%"
            params.extend([term, term, term, term])

        if v_class:
            query_sql += " AND (class_id = ? OR class_id LIKE ?)"
            params.extend([v_class.upper(), f"%{v_class}%"])

        if program:
            query_sql += " AND program LIKE ?"
            params.append(f"%{program}%")

        if weakness:
            query_sql += " AND weakness LIKE ?"
            params.append(f"%{weakness}%")

        if severity:
            query_sql += " AND severity = ?"
            params.append(severity.lower())

        query_sql += " ORDER BY votes DESC, bounty DESC LIMIT ?"
        params.append(limit)

        cur.execute(query_sql, params)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

        if not rows:
            return f"No reports found matching query: {args}"

        lines = [f"### HexBrain Disclosed Reports ({len(rows)} results)\n"]
        for r in rows:
            bounty_str = f"${r['bounty']:,.0f}" if r.get('bounty') else "Undisclosed"
            sev = (r.get('severity') or 'N/A').upper()
            lines.append(f"- **[#{r['id']} {r['title']}](http://localhost:8080/report/{r['id']})**")
            lines.append(f"  - **Program:** {r['program']} | **Severity:** {sev} | **Bounty:** {bounty_str} | **Upvotes:** {r['votes']}")
            lines.append(f"  - **Weakness:** {r['weakness']} (Class: {r['class_id']})")
        return "\n".join(lines)

    elif name == "get_report":
        rid = args.get("report_id")
        cur.execute("SELECT * FROM reports WHERE id = ?", (rid,))
        row = cur.fetchone()
        conn.close()

        if not row:
            return f"Report #{rid} not found in HexBrain database."

        r = dict(row)
        bounty_str = f"${r['bounty']:,.0f}" if r.get('bounty') else "Undisclosed"
        return f"""# Report #{r['id']}: {r['title']}

- **Target Program:** {r['program']}
- **Vulnerability Class:** {r['class_id']} ({r['weakness']})
- **Severity:** {(r.get('severity') or 'N/A').upper()}
- **Bounty Awarded:** {bounty_str}
- **Community Upvotes:** {r['votes']}
- **Disclosure Status:** {r.get('substate', 'Resolved')}

---

### Technical Summary & Write-up
{r.get('writeup') or 'No summary available.'}

### Steps to Reproduce
{r.get('steps_to_reproduce') or 'See write-up for full reproduction procedure.'}

### Business Impact
{r.get('impact') or 'Compromise of security parameters or user integrity.'}

[Open on HackerOne](https://hackerone.com/reports/{r['id']})
"""

    elif name == "list_classes":
        cur.execute("SELECT id, name, count, bounty, weaknesses_count FROM classes ORDER BY count DESC")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

        lines = ["### HexBrain Core Vulnerability Classes (18 Classes)\n"]
        lines.append("| Class ID | Vulnerability Name | Total Reports | Weaknesses | Historical Bounties |")
        lines.append("|---|---|---|---|---|")
        for r in rows:
            lines.append(f"| `{r['id']}` | **{r['name']}** | {r['count']:,} | {r['weaknesses_count']} | ${r['bounty']:,.0f} |")
        return "\n".join(lines)

    elif name == "list_weaknesses":
        v_class = args.get("vulnerability_class")
        if v_class:
            cur.execute("""
            SELECT w.name, w.count, w.bounty, w.tag, c.name as class_name, c.id as class_id
            FROM weaknesses w JOIN classes c ON w.class_id = c.id
            WHERE c.id = ? OR c.name LIKE ?
            ORDER BY w.count DESC
            """, (v_class.upper(), f"%{v_class}%"))
        else:
            cur.execute("""
            SELECT w.name, w.count, w.bounty, w.tag, c.name as class_name, c.id as class_id
            FROM weaknesses w JOIN classes c ON w.class_id = c.id
            ORDER BY w.count DESC LIMIT 40
            """)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

        lines = [f"### Weaknesses ({len(rows)} weaknesses)\n"]
        lines.append("| Weakness | Class | Reports | Total Bounty |")
        lines.append("|---|---|---|---|")
        for r in rows:
            lines.append(f"| {r['name']} | `{r['class_id']}` ({r['class_name']}) | {r['count']:,} | ${r['bounty']:,.0f} |")
        return "\n".join(lines)

    elif name == "list_programs":
        q = args.get("query", "").strip()
        min_reps = args.get("min_reports", 1)
        limit = min(50, max(1, args.get("limit", 20)))

        query_sql = "SELECT name, count, bounty, total_subdomains FROM programs WHERE count >= ?"
        params = [min_reps]

        if q:
            query_sql += " AND name LIKE ?"
            params.append(f"%{q}%")

        query_sql += " ORDER BY count DESC LIMIT ?"
        params.append(limit)

        cur.execute(query_sql, params)
        rows = [dict(r) for r in cur.fetchall()]

        # also fetch sample subdomains for each program
        lines = [f"### Bug Bounty Programs ({len(rows)} results)\n"]
        for r in rows:
            cur.execute("SELECT domain FROM subdomains WHERE program_name = ? LIMIT 3", (r['name'],))
            subs = [s[0] for s in cur.fetchall()]
            subs_str = ", ".join(subs) if subs else "Standard web scope"
            lines.append(f"- **{r['name']}**: {r['count']:,} disclosed reports | Payouts: ${r['bounty']:,.0f} | Subdomains: {r['total_subdomains']:,}")
            lines.append(f"  - *Assets:* `{subs_str}`")

        conn.close()
        return "\n".join(lines)

    elif name == "search_payloads":
        q = args.get("query", "").strip()
        category = args.get("category")
        limit = min(50, max(1, args.get("limit", 10)))

        query_sql = "SELECT category, title, payload, description, variant FROM payloads WHERE 1=1"
        params = []

        if q:
            query_sql += " AND (title LIKE ? OR payload LIKE ? OR description LIKE ?)"
            term = f"%{q}%"
            params.extend([term, term, term])

        if category:
            query_sql += " AND category = ?"
            params.append(category.upper())

        query_sql += " LIMIT ?"
        params.append(limit)

        cur.execute(query_sql, params)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

        if not rows:
            return f"No payloads found for criteria: {args}"

        lines = [f"### Exploit Payloads ({len(rows)} results)\n"]
        for r in rows:
            lines.append(f"#### [{r['category']}] {r['title']} ({r.get('variant', 'General')})")
            lines.append(f"> {r['description']}\n")
            lines.append(f"```text\n{r['payload']}\n```\n")
        return "\n".join(lines)

    elif name == "search_bypasses":
        q = args.get("query", "").strip()
        prot = args.get("protection_type")
        limit = min(50, max(1, args.get("limit", 10)))

        query_sql = "SELECT title, protection_type, vulnerability, technique, program, bounty, report_id, description, code_example FROM bypasses WHERE 1=1"
        params = []

        if q:
            query_sql += " AND (title LIKE ? OR technique LIKE ? OR description LIKE ?)"
            term = f"%{q}%"
            params.extend([term, term, term])

        if prot:
            query_sql += " AND protection_type LIKE ?"
            params.append(f"%{prot}%")

        query_sql += " LIMIT ?"
        params.append(limit)

        cur.execute(query_sql, params)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

        if not rows:
            return f"No bypass techniques found matching: {args}"

        lines = [f"### Bypass & Filter Evasion Techniques ({len(rows)} results)\n"]
        for r in rows:
            lines.append(f"#### {r['title']}")
            lines.append(f"- **Protection:** {r['protection_type']} | **Vulnerability:** {r['vulnerability']} | **Program:** {r.get('program', 'N/A')}")
            lines.append(f"- **Technique:** {r['technique']}")
            if r.get('description'):
                lines.append(f"- **Details:** {r['description']}")
            if r.get('code_example'):
                lines.append(f"```text\n{r['code_example']}\n```")
            lines.append("")
        return "\n".join(lines)

    elif name == "search_cves":
        q = args.get("query", "").strip()
        kev_only = args.get("exploited_in_wild")
        min_cvss = args.get("min_cvss", 0.0)
        limit = min(50, max(1, args.get("limit", 15)))

        query_sql = "SELECT id, title, cvss, product, kev, year, likelihood, description FROM cves WHERE 1=1"
        params = []

        if q:
            query_sql += " AND (id LIKE ? OR title LIKE ? OR product LIKE ?)"
            term = f"%{q}%"
            params.extend([term, term, term])

        if kev_only:
            query_sql += " AND kev = 1"

        if min_cvss > 0:
            query_sql += " AND cvss >= ?"
            params.append(min_cvss)

        query_sql += " ORDER BY kev DESC, cvss DESC LIMIT ?"
        params.append(limit)

        cur.execute(query_sql, params)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

        if not rows:
            return f"No CVEs found for criteria: {args}"

        lines = [f"### Tracked CVEs ({len(rows)} results)\n"]
        lines.append("| CVE ID | Title / Vulnerability | CVSS | KEV (In Wild) | Likelihood |")
        lines.append("|---|---|---|---|---|")
        for r in rows:
            kev_str = "🔥 **YES (CISA KEV)**" if r.get('kev') else "No"
            like_pct = f"{int(r['likelihood'] * 100)}%" if r.get('likelihood') else "N/A"
            lines.append(f"| **{r['id']}** | {r['title']} | `{r['cvss']}` | {kev_str} | {like_pct} |")
        return "\n".join(lines)

    elif name == "sync_live_sources":
        from sync_manager import (
            sync_all_sources, sync_cisa_kev, sync_github_advisories,
            sync_hackerone_disclosures, sync_first_epss, sync_bounty_targets,
            sync_payloads_and_bypasses
        )
        sources = args.get("sources", ["all"])
        results = {}

        if "all" in sources:
            results = sync_all_sources()
        else:
            if "cisa_kev" in sources:
                results["cisa_kev"] = sync_cisa_kev()
            if "github_advisories" in sources:
                results["github_advisories"] = sync_github_advisories()
            if "hackerone_disclosures" in sources:
                results["hackerone_disclosures"] = sync_hackerone_disclosures(limit=None)
            if "first_epss" in sources:
                results["first_epss"] = sync_first_epss(batch_size=50)
            if "bounty_targets" in sources:
                results["bounty_targets"] = sync_bounty_targets()
            if "payloads_bypasses" in sources:
                results["payloads_bypasses"] = sync_payloads_and_bypasses()

        conn.close()
        lines = ["### Live Data Sources Synchronization Report\n"]
        for src, res in results.items():
            if "error" in res:
                lines.append(f"- ❌ **{src}**: Error - `{res['error']}`")
            else:
                lines.append(f"- ✅ **{res.get('source', src)}**: Synchronized successfully!")
                for k, v in res.items():
                    if k != "source":
                        lines.append(f"  - *{k}:* {v}")
        return "\n".join(lines)

    elif name == "get_data_sources_status":
        from sync_manager import get_sync_status
        status = get_sync_status()
        conn.close()

        lines = ["### Connected Security Intelligence Data Sources\n"]
        lines.append(f"**Last Full Synchronization:** `{status.get('last_sync') or 'Never'}`\n")
        lines.append("| Source Name | Feed Type | Current Status | Records | Last Updated |")
        lines.append("|---|---|---|---|---|")
        for k, v in status.get("sources", {}).items():
            lines.append(f"| **{k}** | REST / Live JSON | `{v.get('status')}` | {v.get('count', 0):,} | `{v.get('last_updated') or 'Initial'}` |")
        return "\n".join(lines)

    else:
        conn.close()
        raise ValueError(f"Unknown tool name: {name}")

if __name__ == '__main__':
    # Test initialize & tools/list
    print('Testing initialize...')
    init_res = handle_mcp_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    print('Initialize result:', json.dumps(init_res, indent=2))

    print('\nTesting tools/list...')
    tools_res = handle_mcp_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    print(f'Total tools: {len(tools_res["result"]["tools"])}')

    print('\nTesting tools/call (search_reports)...')
    call_res = handle_mcp_request({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "search_reports",
            "arguments": {"query": "SSRF", "limit": 3}
        }
    })
    print(call_res["result"]["content"][0]["text"])
