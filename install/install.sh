#!/usr/bin/env bash
# ============================================================
# NIGHTFANG -> Hermes Seamless Installer
#
# Transforms Hermes into NIGHTFANG:
# - Injects the NIGHTFANG Security Intelligence Layer persona & constitution
# - Links all 31 security skills & 35+ Python execution tools
# - Configures the Execution Policy Gateway and Sandbox
# - Installs the 'nightfang' launcher CLI
# ============================================================
set -euo pipefail

NIGHTFANG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
NF_HERMES_HOME="$HERMES_HOME/nightfang"
NF_SKILL_LINK="$HERMES_HOME/skills/nightfang"
HERMES_BIN_DIR="$HERMES_HOME/bin"

SYSTEM_PROMPT_SRC="$NIGHTFANG_ROOT/adapters/hermes/system.md"
CONFIG_SRC="$NIGHTFANG_ROOT/adapters/hermes/config.yaml"
MEMORY_SRC="$NIGHTFANG_ROOT/adapters/hermes/memory"

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
success "Linked 31 skills and 35+ tools to $NF_SKILL_LINK"

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
        echo "" >> "$HERMES_HOME/config.yaml"
        echo "# --- NIGHTFANG Extension Configuration ---" >> "$HERMES_HOME/config.yaml"
        cat "$CONFIG_SRC" >> "$HERMES_HOME/config.yaml"
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
touch "$NF_HERMES_HOME/memory/audit.log"
success "Engagement memory storage initialized."

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
    printf '\033[1;35m37 Specialized Agents | 33 Capabilities | Gateway Sandbox: ACTIVE\033[0m\n\n'
fi

if command -v hermes >/dev/null 2>&1; then
    exec hermes --system-prompt "\$HERMES_SYSTEM_PROMPT" --config "\$HERMES_CONFIG" "\$@"
else
    # Fallback to python runner or standalone agent if hermes binary is not in PATH
    echo "[*] Hermes binary not detected in PATH. Starting in NIGHTFANG Gateway Mode..."
    if [ "\$#" -gt 0 ]; then
        python3 "$NIGHTFANG_ROOT/tools/gateway.py" "\$@"
    else
        echo "Usage: nightfang [options] or install 'hermes' to use full agent runtime."
        echo "Interactive Gateway & Sandbox ready."
        python3 -i -c "import sys; sys.path.insert(0, '$NIGHTFANG_ROOT/tools'); from gateway import ExecutionPolicyGateway; print('[✓] ExecutionPolicyGateway imported as gateway.')"
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
  "agents_count": 37,
  "capabilities_count": 33,
  "skills_path": "$NF_SKILL_LINK",
  "system_prompt": "$NF_HERMES_HOME/system.md",
  "config": "$NF_HERMES_HOME/config.yaml",
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
