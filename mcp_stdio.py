#!/usr/bin/env python3
"""
HexBrain MCP Stdio Server
Standard Model Context Protocol stdio transport for local AI assistants
(Claude Desktop, Cursor, Windsurf, Antigravity, etc.).

Usage in claude_desktop_config.json:
{
  "mcpServers": {
    "hexbrain": {
      "command": "python3",
      "args": ["/home/kali/hexbrain-clone/mcp_stdio.py"]
    }
  }
}
"""

import sys
import json
import logging
from mcp_server import handle_mcp_request

logging.basicConfig(level=logging.ERROR, stream=sys.stderr)

def main():
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue

            req = json.loads(line)
            res = handle_mcp_request(req)
            if res is not None:
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
        except KeyboardInterrupt:
            break
        except Exception as e:
            err_res = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }
            sys.stdout.write(json.dumps(err_res) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
