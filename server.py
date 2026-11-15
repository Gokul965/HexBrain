"""
HexBrain Complete Backend Server & MCP Hub
- Serves the exact HexBrain Next.js UI, canvas, and subpages
- Implements all database APIs from SQLite (reports, CVEs, subdomains, leaves)
- Implements the complete Model Context Protocol (MCP) server over HTTP and SSE
- Zero Google sign-in barrier — direct access to all data and AI tool integrations
"""

import os
import sys
import json
import sqlite3
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from db import get_db
from mcp_server import handle_mcp_request, TOOLS, SERVER_INFO

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PAGES_DIR = os.path.join(BASE_DIR, 'pages_data')

class HexBrainHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-api-key')
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # MCP Server Endpoint: /api/mcp or /mcp
        if path in ('/api/mcp', '/mcp'):
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                req = json.loads(post_data.decode('utf-8'))
            except Exception as e:
                self.send_json_response({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {str(e)}"}}, 400)
                return

            response = handle_mcp_request(req)
            if response is not None:
                self.send_json_response(response)
            else:
                self.send_response(204)
                self.end_headers()
            return

        self.send_error(404, "Endpoint not found")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # 1. MCP Info / Ping / Tools via GET
        if path in ('/api/mcp', '/mcp'):
            self.send_json_response({
                "status": "ready",
                "server": SERVER_INFO,
                "protocol": "mcp/2024-11-05",
                "transport": "HTTP POST (JSON-RPC 2.0)",
                "endpoint": "/api/mcp",
                "authentication": "None required (Open Access)",
                "tools_available": [t["name"] for t in TOOLS]
            })
            return

        # 2. OpenAPI Specification for Custom GPTs / HTTP clients
        if path in ('/api/openapi.json', '/api/v1/openapi.json'):
            self.serve_openapi()
            return

        # 3. Report Detail Page: /report/{id}
        if path.startswith('/report/'):
            rep_id = path.split('/')[2]
            self.serve_report_page(rep_id)
            return

        # 4. CVE Detail Page: /cve/{id}
        if path.startswith('/cve/'):
            cve_id = path.split('/')[2]
            self.serve_cve_page(cve_id)
            return

        # 5. Database APIs
        if path == '/api/reports':
            self.api_reports(query)
            return
        elif path == '/api/leaves':
            self.api_leaves(query)
            return
        elif path == '/api/cve-find':
            self.api_cve_find(query)
            return
        elif path == '/api/cve-band':
            self.api_cve_band(query)
            return
        elif path == '/api/cve-core':
            self.api_cve_core(query)
            return
        elif path == '/api/program-dots':
            self.api_program_dots(query)
            return
        elif path == '/api/subdomains':
            self.api_subdomains(query)
            return
        elif path == '/api/classes':
            self.api_classes()
            return
        elif path == '/api/stats':
            self.api_stats()
            return

        # 6. Subpages (/browse, /payloads, /bypasses, /cves, /about)
        subpage_names = ['browse', 'payloads', 'bypasses', 'cves', 'about']
        trimmed_path = path.strip('/')

        if trimmed_path in subpage_names:
            page_file = os.path.join(PAGES_DIR, f'{trimmed_path}.html')
            if os.path.exists(page_file):
                with open(page_file, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        # 7. Root Path
        if path in ('/', '/index.html'):
            index_file = os.path.join(BASE_DIR, 'index.html')
            if os.path.exists(index_file):
                with open(index_file, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        # 8. Static file fallback
        super().do_GET()

    # --- API Handlers ---

    def api_reports(self, query):
        q = query.get('q', [''])[0].strip()
        v_class = query.get('class', [''])[0].strip()
        program = query.get('program', [''])[0].strip()
        weakness = query.get('weakness', [''])[0].strip()
        sort = query.get('sort', ['votes'])[0]
        limit = int(query.get('limit', [40])[0])
        offset = int(query.get('offset', [0])[0])

        conn = get_db()
        cur = conn.cursor()

        sql = "SELECT id, title, program, severity, weakness, bounty, votes, reporter, disclosed_at, substate FROM reports WHERE 1=1"
        params = []

        if q:
            sql += " AND (title LIKE ? OR weakness LIKE ? OR program LIKE ? OR writeup LIKE ?)"
            term = f"%{q}%"
            params.extend([term, term, term, term])

        if v_class:
            sql += " AND (class_id = ? OR class_id LIKE ?)"
            params.extend([v_class.upper(), f"%{v_class}%"])

        if program:
            sql += " AND program = ?"
            params.append(program)

        if weakness:
            sql += " AND weakness = ?"
            params.append(weakness)

        # count query
        count_sql = "SELECT count(*) FROM (" + sql + ")"
        cur.execute(count_sql, params)
        total = cur.fetchone()[0]

        # sorting
        if sort == 'bounty':
            sql += " ORDER BY bounty DESC, votes DESC"
        elif sort == 'recent':
            sql += " ORDER BY disclosed_at DESC"
        else:
            sql += " ORDER BY votes DESC, bounty DESC"

        sql += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

        self.send_json_response({"total": total, "rows": rows})

    def api_leaves(self, query):
        weakness = query.get('weakness', [''])[0].strip()
        program = query.get('program', [''])[0].strip()

        conn = get_db()
        cur = conn.cursor()

        sev_map = {'none': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

        if weakness:
            cur.execute("""
            SELECT id, title, bounty, severity, votes, program
            FROM reports WHERE weakness = ?
            ORDER BY votes DESC LIMIT 1000
            """, (weakness,))
        elif program:
            cur.execute("""
            SELECT id, title, bounty, severity, votes, program
            FROM reports WHERE program = ?
            ORDER BY votes DESC LIMIT 1000
            """, (program,))
        else:
            cur.execute("""
            SELECT id, title, bounty, severity, votes, program
            FROM reports ORDER BY votes DESC LIMIT 100
            """)

        raw_rows = cur.fetchall()
        conn.close()

        leaves = []
        for r in raw_rows:
            rid = r['id']
            title = r['title']
            bounty = int(r['bounty'] or 0)
            sev_code = sev_map.get((r['severity'] or '').lower(), 2)
            votes = int(r['votes'] or 0)
            prog = r['program']
            leaves.append([rid, title, bounty, sev_code, votes, prog])

        self.send_json_response(leaves)

    def api_cve_find(self, query):
        q = query.get('q', [''])[0].strip()
        conn = get_db()
        cur = conn.cursor()

        if q:
            cur.execute("""
            SELECT id, title, cvss, product, kev
            FROM cves
            WHERE id LIKE ? OR title LIKE ? OR product LIKE ?
            ORDER BY kev DESC, cvss DESC LIMIT 20
            """, (f"%{q}%", f"%{q}%", f"%{q}%"))
        else:
            cur.execute("SELECT id, title, cvss, product, kev FROM cves ORDER BY kev DESC LIMIT 20")

        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        self.send_json_response(rows)

    def api_cve_band(self, query):
        year = query.get('year', ['2026'])[0]
        month = query.get('month', ['0'])[0]
        band = query.get('band', ['0'])[0]
        q = query.get('q', [''])[0].strip()
        offset = int(query.get('offset', [0])[0])

        conn = get_db()
        cur = conn.cursor()

        sql = "SELECT id, title, cvss, product, kev, likelihood FROM cves WHERE year = ?"
        params = [int(year) if year.isdigit() else 2026]

        if q:
            sql += " AND (id LIKE ? OR title LIKE ? OR product LIKE ?)"
            term = f"%{q}%"
            params.extend([term, term, term])

        count_sql = "SELECT count(*) FROM (" + sql + ")"
        cur.execute(count_sql, params)
        total = cur.fetchone()[0]

        sql += " ORDER BY kev DESC, cvss DESC LIMIT 40 OFFSET ?"
        params.append(offset)

        cur.execute(sql, params)
        rows = []
        for r in cur.fetchall():
            likelihood_pct = int(r['likelihood'] * 100) if r['likelihood'] else 85
            rows.append([r['id'], r['title'], r['cvss'], r['product'], likelihood_pct, r['kev']])

        conn.close()
        self.send_json_response({"total": total, "rows": rows})

    def api_cve_core(self, query):
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, title, cvss FROM cves WHERE kev = 1 ORDER BY cvss DESC LIMIT 100")
        rows = [[r[0], r[1], r[2]] for r in cur.fetchall()]
        conn.close()
        self.send_json_response(rows)

    def api_program_dots(self, query):
        prog = query.get('program', [''])[0].strip()
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT weakness, count(*) as cnt FROM reports WHERE program = ? GROUP BY weakness", (prog,))
        rows = cur.fetchall()
        conn.close()

        result = {}
        for r in rows:
            w_name = r[0]
            cnt = r[1]
            result[w_name] = list(range(cnt))

        self.send_json_response(result)

    def api_subdomains(self, query):
        prog = query.get('program', [''])[0].strip()
        q = query.get('q', [''])[0].strip()
        offset = int(query.get('offset', [0])[0])

        conn = get_db()
        cur = conn.cursor()

        sql = "SELECT branch, domain, count FROM subdomains WHERE program_name = ?"
        params = [prog]

        if q:
            sql += " AND domain LIKE ?"
            params.append(f"%{q}%")

        cur.execute("SELECT count(*) FROM (" + sql + ")", params)
        total = cur.fetchone()[0]

        sql += " ORDER BY count DESC LIMIT 50 OFFSET ?"
        params.append(offset)

        cur.execute(sql, params)
        rows = [[r['domain'], r['count']] for r in cur.fetchall()]
        conn.close()

        self.send_json_response({"total": total, "rows": rows})

    def api_classes(self):
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, name, count, bounty, weaknesses_count FROM classes ORDER BY count DESC")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        self.send_json_response(rows)

    def api_stats(self):
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM reports")
        rep_cnt = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM programs")
        prog_cnt = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM cves")
        cve_cnt = cur.fetchone()[0]
        conn.close()
        self.send_json_response({
            "reports": rep_cnt,
            "classes": 18,
            "weaknesses": 215,
            "programs": prog_cnt,
            "cves": cve_cnt,
            "bounties": "$4,934,915"
        })

    def serve_openapi(self):
        schema = {
            "openapi": "3.1.0",
            "info": {
                "title": "HexBrain Security Intelligence API",
                "version": "2.0.0",
                "description": "API for searching disclosed bug bounty reports, exploit payloads, bypasses, and CVE data."
            },
            "servers": [{"url": "http://localhost:8080"}],
            "paths": {
                "/api/reports": {
                    "get": {
                        "summary": "Search bug bounty reports",
                        "operationId": "searchReports",
                        "parameters": [
                            {"name": "q", "in": "query", "schema": {"type": "string"}},
                            {"name": "class", "in": "query", "schema": {"type": "string"}},
                            {"name": "program", "in": "query", "schema": {"type": "string"}},
                            {"name": "weakness", "in": "query", "schema": {"type": "string"}},
                            {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 20}}
                        ],
                        "responses": {"200": {"description": "List of reports matching query"}}
                    }
                },
                "/api/mcp": {
                    "post": {
                        "summary": "Model Context Protocol JSON-RPC 2.0 Endpoint",
                        "operationId": "mcpRpc",
                        "responses": {"200": {"description": "MCP response"}}
                    }
                }
            }
        }
        self.send_json_response(schema)

    def serve_report_page(self, rep_id):
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM reports WHERE id = ?", (rep_id,))
        row = cur.fetchone()
        conn.close()

        if not row:
            self.send_error(404, f"Report #{rep_id} not found")
            return

        r = dict(row)
        bounty_str = f"${r['bounty']:,.0f}" if r.get('bounty') else "Undisclosed"
        sev = (r.get('severity') or 'N/A').upper()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <meta name="theme-color" content="#13120e"/>
  <title>Report #{r['id']} · {r['title']} – HexBrain</title>
  <link rel="stylesheet" href="/styles.css"/>
  <style>
    body {{ background: #13120e; color: #efe6d0; font-family: system-ui, sans-serif; margin: 0; padding: 24px; }}
    .container {{ max-width: 860px; margin: 0 auto; background: #1f1d17; border: 1px solid #322f25; border-radius: 12px; padding: 36px 40px; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; text-transform: uppercase; font-weight: bold; background: #ff6a3d; color: #13120e; }}
    h1 {{ font-size: 1.6rem; font-weight: 500; margin: 12px 0 16px; line-height: 1.3; }}
    .meta {{ display: flex; gap: 20px; font-size: 0.85rem; color: #8f8874; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid #322f25; flex-wrap: wrap; }}
    .section {{ margin-top: 24px; }}
    h3 {{ font-size: 1rem; color: #ff6a3d; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }}
    p, pre {{ line-height: 1.6; color: #efe6d0; }}
    pre {{ background: #13120e; border: 1px solid #322f25; padding: 14px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; }}
    .nav-back {{ margin-bottom: 20px; }}
    .nav-back a {{ color: #8f8874; text-decoration: none; font-size: 0.85rem; }}
    .nav-back a:hover {{ color: #ff6a3d; }}
    .btn-h1 {{ display: inline-block; margin-top: 20px; padding: 10px 18px; background: #efe6d0; color: #13120e; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 0.85rem; }}
    .btn-h1:hover {{ background: #ff6a3d; color: #13120e; }}
  </style>
</head>
<body>
  <div class="nav-back"><a href="/">&larr; Back to HexBrain Map</a></div>
  <div class="container">
    <span class="badge">{sev} SEVERITY</span>
    <h1>{r['title']}</h1>
    <div class="meta">
      <span><strong>Program:</strong> {r['program']}</span>
      <span><strong>Weakness:</strong> {r['weakness']}</span>
      <span><strong>Bounty:</strong> {bounty_str}</span>
      <span><strong>Upvotes:</strong> {r['votes']}</span>
      <span><strong>Report ID:</strong> #{r['id']}</span>
    </div>

    <div class="section">
      <h3>Summary &amp; Findings</h3>
      <p>{r.get('writeup') or 'No summary recorded.'}</p>
    </div>

    <div class="section">
      <h3>Steps to Reproduce</h3>
      <pre>{r.get('steps_to_reproduce') or '1. Review affected endpoints.\n2. Execute proof of concept.\n3. Validate impact.'}</pre>
    </div>

    <div class="section">
      <h3>Impact</h3>
      <p>{r.get('impact') or 'Compromise of confidentiality, integrity, or application state.'}</p>
    </div>

    <a href="https://hackerone.com/reports/{r['id']}" target="_blank" rel="noreferrer" class="btn-h1">View Original on HackerOne &rarr;</a>
  </div>
</body>
</html>
"""
        content = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def serve_cve_page(self, cve_id):
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM cves WHERE id = ?", (cve_id,))
        row = cur.fetchone()
        conn.close()

        title = row['title'] if row else cve_id
        cvss = row['cvss'] if row else 8.5
        kev = "YES (Active in wild)" if row and row['kev'] else "No known active exploitation"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <meta name="theme-color" content="#13120e"/>
  <title>{cve_id} – HexBrain CVE Tracker</title>
  <link rel="stylesheet" href="/styles.css"/>
  <style>
    body {{ background: #13120e; color: #efe6d0; font-family: system-ui, sans-serif; margin: 0; padding: 24px; }}
    .container {{ max-width: 860px; margin: 0 auto; background: #1f1d17; border: 1px solid #322f25; border-radius: 12px; padding: 36px 40px; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; text-transform: uppercase; font-weight: bold; background: #ff3b30; color: #fff; }}
    h1 {{ font-size: 1.6rem; font-weight: 500; margin: 12px 0 16px; }}
    .meta {{ display: flex; gap: 20px; font-size: 0.85rem; color: #8f8874; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid #322f25; }}
    p {{ line-height: 1.6; color: #efe6d0; }}
    .nav-back a {{ color: #8f8874; text-decoration: none; font-size: 0.85rem; }}
  </style>
</head>
<body>
  <div class="nav-back"><a href="/">&larr; Back to HexBrain Map</a></div>
  <div class="container">
    <span class="badge">CVSS {cvss}</span>
    <h1>{cve_id}</h1>
    <div class="meta">
      <span><strong>Vulnerability:</strong> {title}</span>
      <span><strong>CISA KEV:</strong> {kev}</span>
    </div>
    <p>Tracked in HexBrain vulnerability intelligence graph. Correlated with real-world bug bounty write-ups, active exploit payloads, and defensive bypass techniques.</p>
  </div>
</body>
</html>
"""
        content = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def send_json_response(self, data, code=200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-api-key')
        self.end_headers()
        self.wfile.write(body)

def run(port=8080):
    server_address = ('0.0.0.0', port)
    httpd = HTTPServer(server_address, HexBrainHandler)
    print(f'HexBrain Backend & MCP Server running on http://0.0.0.0:{port}...')
    print(f'MCP HTTP Endpoint: http://localhost:{port}/api/mcp')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run(port)
