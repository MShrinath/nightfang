#!/usr/bin/env python3
"""taint_trace.py - AST and pattern-based taint tracking models for multi-language security review.

Supports Python (AST + regex), JavaScript, PHP, and Java (regex pattern models).
Used by variant_hunt.py and source code auditing workflows.
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import sys
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Language Pattern Models
# ---------------------------------------------------------------------------

MODEL: Dict[str, Dict[str, Any]] = {
    "py": {
        "func": re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z0-9_]+)\s*\("),
        "sources": [
            r"request\.(GET|POST|args|form|values|json|data|files|headers|cookies)",
            r"sys\.argv",
            r"os\.environ",
            r"input\(",
            r"socket\.recv",
            r"self\.get_argument\(",
            r"request\.body",
        ],
        "sanitizers": [
            r"html\.escape\(",
            r"escape\(",
            r"shlex\.quote\(",
            r"int\(",
            r"float\(",
            r"bleach\.clean\(",
            r"urlparse\(",
            r"secure_filename\(",
            r"parameters\s*=",
            r"isinstance\(",
        ],
        "sinks": {
            "CWE-89": [
                r"\.execute\(",
                r"\.executemany\(",
                r"\.raw\(",
                r"cursor\.execute",
                r"session\.execute",
            ],
            "CWE-78": [
                r"os\.system\(",
                r"subprocess\.Popen\(",
                r"subprocess\.run\(",
                r"subprocess\.call\(",
                r"subprocess\.check_output\(",
                r"os\.popen\(",
            ],
            "CWE-79": [
                r"render_template_string\(",
                r"Markup\(",
                r"HttpResponse\(",
                r"make_response\(",
            ],
            "CWE-22": [
                r"open\(",
                r"os\.path\.join\(",
                r"send_file\(",
                r"send_from_directory\(",
            ],
            "CWE-94": [
                r"eval\(",
                r"exec\(",
                r"compile\(",
            ],
            "CWE-502": [
                r"pickle\.loads\(",
                r"yaml\.load\(",
                r"shelve\.open\(",
            ],
        },
    },
    "js": {
        "func": re.compile(
            r"^\s*(?:function\s+([A-Za-z0-9_$]+)|(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|([A-Za-z0-9_$]+)\s*\([^)]*\)\s*\{)"
        ),
        "sources": [
            r"req\.(query|body|params|headers|cookies)",
            r"process\.argv",
            r"location\.(search|hash|href)",
            r"window\.name",
            r"document\.cookie",
            r"document\.referrer",
            r"event\.data",
        ],
        "sanitizers": [
            r"encodeURIComponent\(",
            r"DOMPurify\.sanitize\(",
            r"parseInt\(",
            r"parseFloat\(",
            r"escapeHtml\(",
            r"validator\.",
            r"Number\(",
            r"sanitize\(",
        ],
        "sinks": {
            "CWE-89": [
                r"\.query\(",
                r"\.execute\(",
                r"sequelize\.query\(",
                r"knex\.raw\(",
                r"db\.all\(",
            ],
            "CWE-78": [
                r"child_process\.exec\(",
                r"child_process\.execSync\(",
                r"child_process\.spawn\(",
                r"execFile\(",
            ],
            "CWE-79": [
                r"innerHTML\s*=",
                r"outerHTML\s*=",
                r"document\.write\(",
                r"res\.send\(",
                r"\$\([^)]+\)\.html\(",
            ],
            "CWE-22": [
                r"fs\.readFile\(",
                r"fs\.readFileSync\(",
                r"fs\.createReadStream\(",
                r"res\.sendFile\(",
            ],
            "CWE-94": [
                r"eval\(",
                r"Function\(",
                r"vm\.runInContext\(",
                r"vm\.runInThisContext\(",
                r"setTimeout\([^,]+,",
            ],
            "CWE-502": [
                r"serialize\.unserialize\(",
                r"node-serialize",
            ],
        },
    },
    "php": {
        "func": re.compile(r"^\s*(?:public|protected|private|static|\s)*function\s+([A-Za-z0-9_]+)\s*\("),
        "sources": [
            r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)",
            r"\$argv",
            r"php://input",
        ],
        "sanitizers": [
            r"htmlspecialchars\(",
            r"htmlentities\(",
            r"intval\(",
            r"floatval\(",
            r"strip_tags\(",
            r"mysqli_real_escape_string\(",
            r"pdo->prepare\(",
            r"filter_var\(",
            r"escapeshellarg\(",
            r"escapeshellcmd\(",
        ],
        "sinks": {
            "CWE-89": [
                r"mysqli_query\(",
                r"mysql_query\(",
                r"->query\(",
                r"->exec\(",
                r"pg_query\(",
            ],
            "CWE-78": [
                r"system\(",
                r"exec\(",
                r"shell_exec\(",
                r"passthru\(",
                r"proc_open\(",
                r"popen\(",
            ],
            "CWE-79": [
                r"echo\s+",
                r"print\s+",
                r"printf\(",
            ],
            "CWE-22": [
                r"include\(",
                r"include_once\(",
                r"require\(",
                r"require_once\(",
                r"file_get_contents\(",
                r"readfile\(",
            ],
            "CWE-94": [
                r"eval\(",
                r"assert\(",
                r"preg_replace\([^,]+,\s*['\"][^'\"]*e",
            ],
            "CWE-502": [
                r"unserialize\(",
            ],
        },
    },
    "java": {
        "func": re.compile(
            r"^\s*(?:public|protected|private|static|final|\s)+[\w<>\[\],\s]+\s+([A-Za-z0-9_]+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{"
        ),
        "sources": [
            r"request\.getParameter\(",
            r"request\.getHeader\(",
            r"request\.getInputStream\(",
            r"@RequestParam",
            r"@PathVariable",
            r"@RequestBody",
            r"System\.getenv\(",
        ],
        "sanitizers": [
            r"HtmlUtils\.htmlEscape\(",
            r"Integer\.parseInt\(",
            r"Long\.parseLong\(",
            r"PreparedStatement",
            r"ESAPI\.encoder\(",
            r"URLEncoder\.encode\(",
        ],
        "sinks": {
            "CWE-89": [
                r"executeQuery\(",
                r"executeUpdate\(",
                r"createNativeQuery\(",
                r"createQuery\(",
            ],
            "CWE-78": [
                r"Runtime\.getRuntime\(\)\.exec\(",
                r"ProcessBuilder\(",
            ],
            "CWE-79": [
                r"response\.getWriter\(\)\.write\(",
                r"response\.getWriter\(\)\.print",
            ],
            "CWE-22": [
                r"new\s+File\(",
                r"new\s+FileInputStream\(",
                r"Paths\.get\(",
            ],
            "CWE-94": [
                r"Method\.invoke\(",
                r"ScriptEngine\.eval\(",
            ],
            "CWE-502": [
                r"ObjectInputStream\.readObject\(",
                r"XMLDecoder\.readObject\(",
            ],
        },
    },
}

# Language file extension mapping
EXT_TO_LANG: Dict[str, str] = {
    ".py": "py",
    ".js": "js",
    ".jsx": "js",
    ".ts": "js",
    ".tsx": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".php": "php",
    ".phtml": "php",
    ".java": "java",
}

IGNORE_DIRS: Set[str] = {
    ".git", ".svn", ".hg", "node_modules", "venv", ".venv", "env",
    "__pycache__", ".pytest_cache", ".tox", "dist", "build", ".idea", ".vscode"
}


def scan_lines(path: str) -> List[str]:
    """Read all lines from path with UTF-8 decoding and graceful fallback."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    except Exception:
        return []


def lang_for(path: str) -> Optional[str]:
    """Return language identifier ('py', 'js', 'php', 'java') or None."""
    _, ext = os.path.splitext(path.lower())
    return EXT_TO_LANG.get(ext)


def iter_files(root: str, langs: List[str]) -> Iterator[str]:
    """Iterate over files under root whose language is in langs."""
    target_langs = set(langs)
    if os.path.isfile(root):
        L = lang_for(root)
        if L and L in target_langs:
            yield root
        return

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for f in filenames:
            p = os.path.join(dirpath, f)
            L = lang_for(p)
            if L and L in target_langs:
                yield p


# ---------------------------------------------------------------------------
# Python AST Taint Analysis Model
# ---------------------------------------------------------------------------

class PythonASTTaintVisitor(ast.NodeVisitor):
    """AST-based taint tracking for Python source trees."""

    def __init__(self):
        self.sources: List[Dict[str, Any]] = []
        self.sinks: List[Dict[str, Any]] = []
        self.assignments: Dict[str, ast.AST] = {}

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.assignments[target.id] = node.value
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # Check against common Python sinks
        for cwe, pats in MODEL["py"]["sinks"].items():
            for pat in pats:
                clean_pat = pat.replace(r"\.", "").replace(r"\(", "")
                if clean_pat in func_name:
                    self.sinks.append({
                        "line": getattr(node, "lineno", 0),
                        "cwe": cwe,
                        "function": func_name,
                    })
        self.generic_visit(node)


def trace_python_ast(source_code: str) -> Dict[str, Any]:
    """Parse Python source into AST and extract call sites and sinks."""
    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        return {"error": str(e), "sinks": []}

    visitor = PythonASTTaintVisitor()
    visitor.visit(tree)
    return {
        "sinks": visitor.sinks,
        "assigned_vars": list(visitor.assignments.keys()),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="NIGHTFANG Taint Trace Engine")
    parser.add_argument("--file", help="Source file to inspect")
    parser.add_argument("--lang", default="py,js,php,java", help="Languages to support")
    args = parser.parse_args(argv)

    if args.file and os.path.exists(args.file):
        L = lang_for(args.file)
        lines = scan_lines(args.file)
        print(f"File: {args.file} (detected lang: {L}, lines: {len(lines)})")
        if L == "py":
            res = trace_python_ast("".join(lines))
            print(f"AST Sinks Found: {len(res.get('sinks', []))}")
    else:
        print("taint_trace: models loaded for " + ", ".join(MODEL.keys()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
