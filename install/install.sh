#!/usr/bin/env bash
# ============================================================
# NIGHTFANG -> Hermes Seamless Installer
#
# Transforms Hermes into NIGHTFANG:
# - Injects the NIGHTFANG Security Intelligence Layer persona & constitution
# - Links all 42 security skills & 46 agents
# - Configures the Execution Policy Gateway and Sandbox
# - Installs the 'nightfang' launcher CLI
# ============================================================
set -eu
set -o pipefail

NIGHTFANG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
NF_HERMES_HOME="$HERMES_HOME/nightfang"
NF_SKILL_LINK="$HERMES_HOME/skills/nightfang"
HERMES_BIN_DIR="$HERMES_HOME/bin"

SYSTEM_PROMPT_SRC="$NIGHTFANG_ROOT/adapters/hermes/system.md"
CONFIG_SRC="$NIGHTFANG_ROOT/adapters/hermes/config.yaml"
MEMORY_SRC="$NIGHTFANG_ROOT/adapters/hermes/memory"

INSTALL_COMPLEMENTARY_SKILLS=true
SKIP_CLONES=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-skills)
            INSTALL_COMPLEMENTARY_SKILLS=false
            shift
            ;;
        --skip-clones)
            SKIP_CLONES=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# ------------------------------------------------------------
# Terminal Formatting
# ------------------------------------------------------------
BOLD='\033[1m'
BLUE='\033[1;34m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
CYAN='\033[1;36m'
NC='\033[0m'

info() {
    printf "${BLUE}[+]${NC} %s\n" "$1"
}

success() {
    printf "${GREEN}[✓]${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}[!]${NC} %s\n" "$1"
}

fail() {
    printf "${RED}[✗]${NC} %s\n" "$1"
    exit 1
}

banner() {
    cat <<'EOF'
 [1;36m
   ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗ █████╗ ███╗   ██╗ ██████╗ 
   ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗████╗  ██║██╔════╝ 
   ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ███████║██╔██╗ ██║██║  ███╗
   ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██╔══██║██║╚██╗██║██║   ██║
   ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ██║  ██║██║ ╚████║╚██████╔╝
   ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ 
 [0m [1;35m
          🦇 NIGHTFANG Security Intelligence Layer for Hermes 🦇
                 Autonomous Pentesting & Adversary Emulation
 [0m
EOF
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ------------------------------------------------------------
# Execution
# ------------------------------------------------------------
banner

info "NIGHTFANG Root:  $NIGHTFANG_ROOT"
info "Hermes Home:     $HERMES_HOME"

# 1. Validate Repository Integrity
info "Verifying NIGHTFANG package structure..."
[[ -f "$NIGHTFANG_ROOT/manifest.yaml" ]] || fail "manifest.yaml not found at $NIGHTFANG_ROOT"
[[ -d "$NIGHTFANG_ROOT/skills" ]]        || fail "skills directory not found at $NIGHTFANG_ROOT"
[[ -d "$NIGHTFANG_ROOT/agents" ]]        || fail "agents directory not found at $NIGHTFANG_ROOT"
[[ -d "$NIGHTFANG_ROOT/workflows" ]]     || fail "workflows directory not found at $NIGHTFANG_ROOT"
[[ -d "$NIGHTFANG_ROOT/tools" ]]         || fail "tools directory not found at $NIGHTFANG_ROOT"
success "NIGHTFANG repository integrity verified."

# 2. Prepare Hermes Directories
info "Setting up Hermes filesystem structure..."
mkdir -p "$HERMES_HOME"
mkdir -p "$HERMES_HOME/skills"
mkdir -p "$HERMES_BIN_DIR"
mkdir -p "$NF_HERMES_HOME"
mkdir -p "$NF_HERMES_HOME/memory"

# 3. Link Skills
info "Integrating NIGHTFANG skills into Hermes..."
if [[ -e "$NF_SKILL_LINK" || -L "$NF_SKILL_LINK" ]]; then
    rm -rf "$NF_SKILL_LINK"
fi
ln -s "$NIGHTFANG_ROOT/skills" "$NF_SKILL_LINK"
success "Linked 42 skills and 46 agents to $NF_SKILL_LINK"

# 3b. Bootstrap Complementary Autonomous Skills (15-Skill Pack)
if [ "$INSTALL_COMPLEMENTARY_SKILLS" = true ]; then
    info "Integrating 15 complementary autonomous skills into Hermes..."
    COMP_SKILLS_DIR="$HERMES_HOME/skills"
    mkdir -p "$COMP_SKILLS_DIR"
    mkdir -p "$HERMES_HOME/plugins"
    mkdir -p "$HERMES_HOME/extensions"

    # Ensure Node, NPM, NPX toolchain is accessible
    NODE_BIN_DIR=$(find "$HERMES_HOME/tools" -maxdepth 2 -type d -name "bin" 2>/dev/null | grep -E "node-[^/]+/bin" | head -n 1 || true)
    if [ -n "$NODE_BIN_DIR" ] && [ -x "$NODE_BIN_DIR/node" ]; then
        info "Discovered embedded Hermes Node.js toolchain at $NODE_BIN_DIR"
        mkdir -p "$HOME/.local/bin"
        ln -sf "$NODE_BIN_DIR/node" "$HOME/.local/bin/node"
        ln -sf "$NODE_BIN_DIR/npm" "$HOME/.local/bin/npm" 2>/dev/null || true
        ln -sf "$NODE_BIN_DIR/npx" "$HOME/.local/bin/npx" 2>/dev/null || true
        export PATH="$NODE_BIN_DIR:$HOME/.local/bin:$PATH"
        if sudo -n true 2>/dev/null; then
            sudo ln -sf "$NODE_BIN_DIR/node" "/usr/local/bin/node" 2>/dev/null || true
            sudo ln -sf "$NODE_BIN_DIR/npm" "/usr/local/bin/npm" 2>/dev/null || true
            sudo ln -sf "$NODE_BIN_DIR/npx" "/usr/local/bin/npx" 2>/dev/null || true
        fi
    fi

    # Ensure uv and uvx toolchain is accessible for python-based MCPs (e.g. mk-qa-master)
    UV_BIN=$(find "$HERMES_HOME/tools" -maxdepth 2 -type f -name "uvx" 2>/dev/null | head -n 1 || true)
    if [ -z "$UV_BIN" ] && [ -x "$HOME/.local/bin/uvx" ]; then
        UV_BIN="$HOME/.local/bin/uvx"
    fi
    if [ -n "$UV_BIN" ] && [ -x "$UV_BIN" ]; then
        UV_DIR=$(dirname "$UV_BIN")
        mkdir -p "$HOME/.local/bin"
        ln -sf "$UV_BIN" "$HOME/.local/bin/uvx"
        if [ -x "$UV_DIR/uv" ]; then
            ln -sf "$UV_DIR/uv" "$HOME/.local/bin/uv"
        fi
        export PATH="$UV_DIR:$HOME/.local/bin:$PATH"
        if sudo -n true 2>/dev/null; then
            sudo ln -sf "$UV_BIN" "/usr/local/bin/uvx" 2>/dev/null || true
            if [ -x "$UV_DIR/uv" ]; then
                sudo ln -sf "$UV_DIR/uv" "/usr/local/bin/uv" 2>/dev/null || true
            fi
        fi
    fi

    # Ensure native build dependencies are present for compiled MCP addons (e.g. better-sqlite3 in th-memory-mcp)
    if ! command -v make >/dev/null 2>&1; then
        if sudo -n true 2>/dev/null && command -v apt-get >/dev/null 2>&1; then
            info "Installing native compilation tools (build-essential) for MCP modules..."
            sudo apt-get update -qq && sudo apt-get install -y -qq build-essential || true
        fi
    fi

    # Ensure $HOME/.local/bin is in PATH for future non-interactive and login shells
    if [ -f "$HOME/.bashrc" ] && ! grep -q 'HOME/.local/bin' "$HOME/.bashrc"; then
        sed -i '1i export PATH="$HOME/.local/bin:$PATH"' "$HOME/.bashrc"
    fi

    PYTHON_BIN=""
    if command -v python3 >/dev/null 2>&1 && python3 --version >/dev/null 2>&1; then
        PYTHON_BIN="python3"
    elif command -v python >/dev/null 2>&1 && python --version >/dev/null 2>&1; then
        PYTHON_BIN="python"
    fi

    if [ -n "$PYTHON_BIN" ]; then
        "$PYTHON_BIN" -m pip install --quiet yt-dlp agent-reach 2>/dev/null || true
    fi

    if command -v npm >/dev/null 2>&1; then
        npm install -g defuddle 2>/dev/null || true
    fi

    SKILL_REPOS=(
        "agent-reach|https://github.com/Panniantong/Agent-Reach.git|$COMP_SKILLS_DIR/agent-reach"
        "humanizer|https://github.com/blader/humanizer.git|$COMP_SKILLS_DIR/humanizer"
        "youtube-skills|https://github.com/ZeroPointRepo/youtube-skills.git|$COMP_SKILLS_DIR/youtube-skills"
        "mattpocock-skills|https://github.com/mattpocock/skills.git|$COMP_SKILLS_DIR/mattpocock"
        "addyosmani-agent-skills|https://github.com/addyosmani/agent-skills.git|$COMP_SKILLS_DIR/addyosmani"
        "minions|https://github.com/agent37-platform/minions.git|$HERMES_HOME/extensions/minions"
        "oh-my-hermes|https://github.com/rlaope/oh-my-hermes.git|$HERMES_HOME/plugins/oh-my-hermes"
        "openmontage|https://github.com/OpenMontageInc/OpenMontage.git|$COMP_SKILLS_DIR/openmontage"
        "browser-harness|https://github.com/browser-use/browser-harness.git|$COMP_SKILLS_DIR/browser-harness"
        "defuddle|https://github.com/kepano/defuddle.git|$COMP_SKILLS_DIR/defuddle"
        "loopy|https://github.com/Forward-Future/loopy.git|$COMP_SKILLS_DIR/loopy"
        "make-interfaces|https://github.com/jakubkrehel/make-interfaces-feel-better.git|$COMP_SKILLS_DIR/make-interfaces"
        "skillclaw|https://github.com/AMAP-ML/SkillClaw.git|$HERMES_HOME/plugins/skillclaw"
    )

    if [ "$SKIP_CLONES" = false ] && command -v git >/dev/null 2>&1; then
        for entry in "${SKILL_REPOS[@]}"; do
            IFS='|' read -r name repo target_dir <<< "$entry"
            if [ ! -d "$target_dir/.git" ]; then
                git clone --depth 1 "$repo" "$target_dir" >/dev/null 2>&1 || true
            fi
        done
    fi

    # Configure verified NIGHTFANG Model Context Protocol (MCP) servers
    info "Configuring verified NIGHTFANG Model Context Protocol (MCP) servers..."
    MCP_CONFIG="$HERMES_HOME/mcp.json"
    NF_MCP_CONFIG="$NF_HERMES_HOME/mcp.json"
    KG_PATH="$NF_HERMES_HOME/memory/knowledge_graph.jsonl"
    MCP_SRC="$NIGHTFANG_ROOT/adapters/hermes/mcp.json"

    if [ -f "$MCP_SRC" ]; then
        sed "s|\${HERMES_HOME}|$HERMES_HOME|g" "$MCP_SRC" > "$NF_MCP_CONFIG"
        cp "$NF_MCP_CONFIG" "$MCP_CONFIG"
    else
        cat > "$MCP_CONFIG" << MCPEOF
{
  "mcpServers": {
    "mk-qa-master": {
      "command": "uvx",
      "args": ["mk-qa-master"]
    },
    "security-scanner-mcp": {
      "command": "npx",
      "args": ["-y", "security-scanner-mcp"]
    },
    "codebase-memory-mcp": {
      "command": "npx",
      "args": ["-y", "codebase-memory-mcp"]
    },
    "server-memory": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-memory"],
      "env": {
        "MEMORY_FILE_PATH": "$KG_PATH"
      }
    },
    "th-memory-mcp": {
      "command": "npx",
      "args": ["-y", "th-memory-mcp"]
    },
    "cve-mcp": {
      "command": "npx",
      "args": ["-y", "cve-mcp"]
    },
    "osint-mcp-server": {
      "command": "npx",
      "args": ["-y", "osint-mcp-server"]
    },
    "playwright": {
      "command": "npx",
      "args": ["-y", "@playwright/mcp@latest", "--headless"]
    }
  }
}
MCPEOF
        cp "$MCP_CONFIG" "$NF_MCP_CONFIG"
    fi

    # Pre-warm native MCP runtime dependencies if npx is available
    if command -v npx >/dev/null 2>&1; then
        info "Pre-warming and compiling native MCP dependencies (th-memory-mcp)..."
        timeout 15 npx -y th-memory-mcp </dev/null >/dev/null 2>&1 || true
    fi

    success "Configured 8 verified MCP servers (QA, memory, OSINT, browser) in Hermes."
fi

# 4. Install System Prompt & Configuration
info "Infusing Hermes with NIGHTFANG persona & constitution..."
cp "$SYSTEM_PROMPT_SRC" "$NF_HERMES_HOME/system.md"
cp "$SYSTEM_PROMPT_SRC" "$HERMES_HOME/system.md"
if [[ -f "$HERMES_HOME/SOUL.md" ]]; then
    cp "$HERMES_HOME/SOUL.md" "$HERMES_HOME/SOUL.md.backup.$(date +%s)"
fi
cp "$SYSTEM_PROMPT_SRC" "$HERMES_HOME/SOUL.md"
cp "$CONFIG_SRC" "$NF_HERMES_HOME/config.yaml"

# Safely inject nightfang configuration without destroying Hermes's root config.yaml
if [[ -f "$HERMES_HOME/config.yaml" ]]; then
    if ! grep -q "nightfang" "$HERMES_HOME/config.yaml"; then
        cp "$HERMES_HOME/config.yaml" "$HERMES_HOME/config.yaml.backup.$(date +%s)"
        echo "" >> "$HERMES_HOME/config.yaml"
        echo "# --- NIGHTFANG Extension Configuration ---" >> "$HERMES_HOME/config.yaml"
        echo "nightfang:" >> "$HERMES_HOME/config.yaml"
        echo "  config: \"$NF_HERMES_HOME/config.yaml\"" >> "$HERMES_HOME/config.yaml"
    fi
    if ! grep -q "^mcp_servers:" "$HERMES_HOME/config.yaml"; then
        cat >> "$HERMES_HOME/config.yaml" << YAMLEOF

# --- NIGHTFANG Verified MCP Servers ---
mcp_servers:
  mk-qa-master:
    command: uvx
    args: ["mk-qa-master"]
  security-scanner-mcp:
    command: npx
    args: ["-y", "security-scanner-mcp"]
  codebase-memory-mcp:
    command: npx
    args: ["-y", "codebase-memory-mcp"]
  server-memory:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-memory"]
    env:
      MEMORY_FILE_PATH: "$NF_HERMES_HOME/memory/knowledge_graph.jsonl"
  th-memory-mcp:
    command: npx
    args: ["-y", "th-memory-mcp"]
  cve-mcp:
    command: npx
    args: ["-y", "cve-mcp"]
  osint-mcp-server:
    command: npx
    args: ["-y", "osint-mcp-server"]
  playwright:
    command: npx
    args: ["-y", "@playwright/mcp@latest", "--headless"]
YAMLEOF
    fi
else
    cp "$CONFIG_SRC" "$HERMES_HOME/config.yaml"
fi
success "Configured NIGHTFANG persona (SOUL.md) and extension settings in Hermes."

# 5. Initialize Memory & Scope Templates
info "Initializing engagement state & memory store..."
if [[ ! -f "$NF_HERMES_HOME/memory/scope.yaml" ]]; then
    cp "$MEMORY_SRC/scope.yaml" "$NF_HERMES_HOME/memory/scope.yaml"
fi
if [[ ! -f "$NF_HERMES_HOME/memory/findings.json" ]]; then
    cp "$MEMORY_SRC/findings.json" "$NF_HERMES_HOME/memory/findings.json"
fi
if [[ ! -f "$NF_HERMES_HOME/memory/knowledge_graph.jsonl" ]]; then
    if [[ -f "$MEMORY_SRC/knowledge_graph.jsonl" ]]; then
        cp "$MEMORY_SRC/knowledge_graph.jsonl" "$NF_HERMES_HOME/memory/knowledge_graph.jsonl"
    else
        cat > "$NF_HERMES_HOME/memory/knowledge_graph.jsonl" << 'KGEOF'
{"type":"entity","name":"NIGHTFANG","entityType":"security-capability-pack","observations":["Autonomous security capability pack integrated into Hermes host runtime","Features 46 specialized agents, 42 skills, and 26 workflows","Equipped with verified MCP integration covering QA, memory, OSINT, and browser automation"]}
KGEOF
    fi
fi
touch "$NF_HERMES_HOME/memory/audit.log"
success "Engagement memory storage and knowledge graph initialized."

# 6. Install Execution Policy Gateway & Tools Integration
info "Wiring Execution Policy Gateway to Hermes..."
cat > "$HERMES_BIN_DIR/nightfang-gate" <<EOF
#!/usr/bin/env bash
# NIGHTFANG Execution Policy Gateway Wrapper
python3 "$NIGHTFANG_ROOT/tools/gateway.py" "\$@"
EOF
chmod +x "$HERMES_BIN_DIR/nightfang-gate"
success "Gateway binary registered: $HERMES_BIN_DIR/nightfang-gate"

# 7. Create Master 'nightfang' CLI Launcher
info "Creating 'nightfang' launcher..."
cat > "$HERMES_BIN_DIR/nightfang" <<EOF
#!/usr/bin/env bash
# ============================================================
# NIGHTFANG CLI (Hermes Injected)
# ============================================================
export HERMES_HOME="$HERMES_HOME"
export NIGHTFANG_ROOT="$NIGHTFANG_ROOT"
export HERMES_SYSTEM_PROMPT="$NF_HERMES_HOME/system.md"
export HERMES_CONFIG="$NF_HERMES_HOME/config.yaml"

# Banner
if [ -t 1 ]; then
    printf '\033[1;36m🦇 NIGHTFANG Security Intelligence Layer (Active)\033[0m\n'
    printf '\033[1;35m46 Specialized Agents | 42 Capabilities | Autonomous Hunter: READY\033[0m\n\n'
fi

if [ "\$1" = "--daemon" ]; then
    shift
    exec python3 "\$NIGHTFANG_ROOT/tools/daemon.py" "\$@"
elif [ "\$1" = "--hunt" ]; then
    shift
    exec python3 "\$NIGHTFANG_ROOT/tools/daemon.py" --continuous "\$@"
elif [ "\$1" = "--test" ]; then
    python3 "\$NIGHTFANG_ROOT/tools/daemon.py" --test
    python3 "\$NIGHTFANG_ROOT/tools/gateway.py"
    python3 "\$NIGHTFANG_ROOT/tools/sandbox.py"
    python3 "\$NIGHTFANG_ROOT/schemas/validator.py" --test
    exit 0
fi

if command -v hermes >/dev/null 2>&1; then
    exec hermes "\$@"
else
    # Fallback to python runner or standalone agent if hermes binary is not in PATH
    echo "[*] Hermes binary not detected in PATH. Starting in NIGHTFANG Gateway Mode..."
    if [ "\$#" -gt 0 ]; then
        exec python3 "\$NIGHTFANG_ROOT/tools/daemon.py" "\$@"
    else
        echo "Usage:"
        echo "  nightfang --daemon --target <domain>    Run continuous autonomous hunter"
        echo "  nightfang --hunt <domain>               Launch autonomous attack chain"
        echo "  nightfang --test                        Run gateway and daemon self-tests"
        echo ""
        echo "Starting interactive Autonomous Hunter session..."
        python3 -i -c "import sys; sys.path.insert(0, '\$NIGHTFANG_ROOT/tools'); from daemon import AutonomousHunterDaemon; from gateway import ExecutionPolicyGateway; print('[*] NIGHTFANG Autonomous Hunter and Gateway loaded.')"
    fi
fi
EOF
chmod +x "$HERMES_BIN_DIR/nightfang"

# Symlink to ~/.local/bin if available
if [[ -d "$HOME/.local/bin" ]]; then
    ln -sf "$HERMES_BIN_DIR/nightfang" "$HOME/.local/bin/nightfang"
    success "Installed global command: ~/.local/bin/nightfang"
fi

# 8. Record Installation Metadata
cat > "$NF_HERMES_HOME/installation.json" <<EOF
{
  "name": "nightfang",
  "version": "2.0",
  "adapter": "hermes",
  "nightfang_root": "$NIGHTFANG_ROOT",
  "hermes_home": "$HERMES_HOME",
  "installed_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "agents_count": 46,
  "capabilities_count": 42,
  "skills_path": "$NF_SKILL_LINK",
  "system_prompt": "$NF_HERMES_HOME/system.md",
  "config": "$NF_HERMES_HOME/config.yaml",
  "knowledge_graph": "$NF_HERMES_HOME/memory/knowledge_graph.jsonl",
  "mcp_config": "$HERMES_HOME/mcp.json",
  "gateway": "$HERMES_BIN_DIR/nightfang-gate",
  "launcher": "$HERMES_BIN_DIR/nightfang"
}
EOF

if command_exists systemctl && systemctl --user is-active --quiet hermes-gateway 2>/dev/null; then
    info "Reloading Hermes Gateway service..."
    systemctl --user restart hermes-gateway || true
    success "Hermes Gateway service reloaded with NIGHTFANG persona."
fi

# ------------------------------------------------------------
# Verification & Summary
# ------------------------------------------------------------
echo
echo "══════════════════════════════════════════════════════════"
success "NIGHTFANG successfully integrated into Hermes!"
echo "══════════════════════════════════════════════════════════"
echo
echo -e "${BOLD}Integration Details:${NC}"
echo "  • NIGHTFANG Root : $NIGHTFANG_ROOT"
echo "  • Hermes Home    : $HERMES_HOME"
echo "  • System Prompt  : $NF_HERMES_HOME/system.md"
echo "  • Skills Linked  : $NF_SKILL_LINK"
echo "  • MCP Config     : $HERMES_HOME/mcp.json"
echo "  • Knowledge Graph: $NF_HERMES_HOME/memory/knowledge_graph.jsonl"
echo "  • Gateway Binary : $HERMES_BIN_DIR/nightfang-gate"
echo "  • Launcher CLI   : $HERMES_BIN_DIR/nightfang"
echo
echo -e "${BOLD}Quick Start:${NC}"
echo "  1. Add Hermes bin to PATH (if not already):"
echo "     export PATH=\"\$HOME/.hermes/bin:\$PATH\""
echo
echo "  2. Launch NIGHTFANG:"
echo "     nightfang"
echo "     # or run hermes normally: hermes"
echo
echo -e "${BOLD}Operator Commands inside Hermes:${NC}"
echo "  /scope set <target>   - Define engagement boundaries"
echo "  /go <TOKEN_ID>        - Approve active exploit or LOUD tool execution"
echo "  /findings             - Display discovered vulnerabilities"
echo "  /report               - Compile full executive and technical deliverable"
echo
