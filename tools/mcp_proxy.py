#!/usr/bin/env python3
"""
NIGHTFANG MCP Gateway Policy Interceptor & Proxy Middleware (tools/mcp_proxy.py)
[DEPRECATED] Consolidated into tools/gateway.py.
This module is maintained as a backward-compatibility shim.
"""

from __future__ import annotations

import sys
try:
    from tools.gateway import (
        MCPGatewayProxy,
        DANGEROUS_MCP_TOOLS,
        run_mcp_proxy_tests as run_self_tests,
    )
except ImportError:
    from gateway import (
        MCPGatewayProxy,
        DANGEROUS_MCP_TOOLS,
        run_mcp_proxy_tests as run_self_tests,
    )

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NIGHTFANG MCP Gateway Policy Interceptor (Compatibility Shim)")
    parser.add_argument("--test", action="store_true", help="Run automated self-tests")
    parser.add_argument("--stdio", action="store_true", help="Run stdio JSON-RPC proxy middleware loop")
    args = parser.parse_args()

    if args.stdio:
        proxy = MCPGatewayProxy()
        proxy.run_proxy()
        sys.exit(0)

    success = run_self_tests()
    sys.exit(0 if success else 1)
