```bash
#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NIGHTFANG -> Hermes Adapter
#
# Installs NIGHTFANG capabilities into an existing Hermes
# installation without modifying the Hermes source tree.
#
# Layout:
#   NIGHTFANG/
#   └── adapters/hermes/install.sh
#
# Result:
#   ~/.hermes/skills/nightfang -> NIGHTFANG/skills
#   ~/.hermes/nightfang/       -> NIGHTFANG Hermes adapter data
# ============================================================

NIGHTFANG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
NF_HERMES_HOME="$HERMES_HOME/nightfang"
NF_SKILL_LINK="$HERMES_HOME/skills/nightfang"

SYSTEM_PROMPT_SRC="$NIGHTFANG_ROOT/adapters/hermes/system.md"
MEMORY_SRC="$NIGHTFANG_ROOT/adapters/hermes/memory"

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

info() {
    printf '\033[1;34m[+]\033[0m %s\n' "$1"
}

success() {
    printf '\033[1;32m[✓]\033[0m %s\n' "$1"
}

warn() {
    printf '\033[1;33m[!]\033[0m %s\n' "$1"
}

fail() {
    printf '\033[1;31m[✗]\033[0m %s\n' "$1"
    exit 1
}

banner() {
    cat <<'EOF'

╔══════════════════════════════════════════════════╗
║                                                  ║
║          NIGHTFANG → HERMES ADAPTER             ║
║                                                  ║
║     Load NIGHTFANG into the Hermes runtime      ║
║                                                  ║
╚══════════════════════════════════════════════════╝

EOF
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ------------------------------------------------------------
# Banner
# ------------------------------------------------------------

banner

info "NIGHTFANG root: $NIGHTFANG_ROOT"
info "Hermes home:    $HERMES_HOME"

# ------------------------------------------------------------
# Check prerequisites
# ------------------------------------------------------------

if ! command_exists git; then
    fail "git is required but was not found."
fi

if ! command_exists python3; then
    warn "python3 was not found. Continuing because the adapter itself does not require Python."
fi

# ------------------------------------------------------------
# Detect Hermes
# ------------------------------------------------------------

info "Detecting Hermes..."

HERMES_FOUND=0

if command_exists hermes; then
    HERMES_FOUND=1
    HERMES_BIN="$(command -v hermes)"
    success "Hermes command found: $HERMES_BIN"
elif [[ -d "$HERMES_HOME" ]]; then
    HERMES_FOUND=1
    success "Hermes directory found: $HERMES_HOME"
else
    warn "Hermes was not detected."
    echo
    echo "Install Hermes first, then run this script again."
    echo
    exit 1
fi

# ------------------------------------------------------------
# Validate NIGHTFANG
# ------------------------------------------------------------

info "Validating NIGHTFANG repository..."

[[ -d "$NIGHTFANG_ROOT" ]] || fail "NIGHTFANG root does not exist."

if [[ ! -d "$NIGHTFANG_ROOT/skills" ]]; then
    warn "NIGHTFANG skills directory not found:"
    warn "$NIGHTFANG_ROOT/skills"
else
    success "NIGHTFANG skills found."
fi

if [[ ! -d "$NIGHTFANG_ROOT/workflows" ]]; then
    warn "NIGHTFANG workflows directory not found."
else
    success "NIGHTFANG workflows found."
fi

if [[ ! -d "$NIGHTFANG_ROOT/policies" ]]; then
    warn "NIGHTFANG policies directory not found."
else
    success "NIGHTFANG policies found."
fi

# ------------------------------------------------------------
# Create Hermes directories
# ------------------------------------------------------------

info "Creating Hermes NIGHTFANG directories..."

mkdir -p "$HERMES_HOME"
mkdir -p "$HERMES_HOME/skills"
mkdir -p "$NF_HERMES_HOME"

success "Directories ready."

# ------------------------------------------------------------
# Backup existing NIGHTFANG integration
# ------------------------------------------------------------

if [[ -e "$NF_SKILL_LINK" || -L "$NF_SKILL_LINK" ]]; then

    if [[ -L "$NF_SKILL_LINK" ]]; then
        CURRENT_TARGET="$(readlink "$NF_SKILL_LINK")"

        if [[ "$CURRENT_TARGET" == "$NIGHTFANG_ROOT/skills" ]]; then
            info "Existing NIGHTFANG skill link already points to this repository."
        else
            warn "Existing NIGHTFANG skill link detected."
            warn "Moving it to a backup."

            BACKUP="$NF_SKILL_LINK.backup.$(date +%Y%m%d%H%M%S)"
            mv "$NF_SKILL_LINK" "$BACKUP"

            success "Backup created: $BACKUP"
        fi

    else
        warn "Existing NIGHTFANG directory detected."

        BACKUP="$NF_SKILL_LINK.backup.$(date +%Y%m%d%H%M%S)"
        mv "$NF_SKILL_LINK" "$BACKUP"

        success "Backup created: $BACKUP"
    fi
fi

# ------------------------------------------------------------
# Link NIGHTFANG skills
# ------------------------------------------------------------

if [[ -d "$NIGHTFANG_ROOT/skills" ]]; then

    if [[ ! -L "$NF_SKILL_LINK" ]]; then
        ln -s "$NIGHTFANG_ROOT/skills" "$NF_SKILL_LINK"
        success "NIGHTFANG skills linked into Hermes."
    fi

else
    warn "Skipping skills because the directory does not exist."
fi

# ------------------------------------------------------------
# Install NIGHTFANG adapter data
# ------------------------------------------------------------

info "Installing adapter configuration..."

mkdir -p "$NF_HERMES_HOME"

# System prompt
if [[ -f "$SYSTEM_PROMPT_SRC" ]]; then

    cp "$SYSTEM_PROMPT_SRC" \
       "$NF_HERMES_HOME/system.md"

    success "NIGHTFANG system context installed."

else
    warn "system.md not found."
    warn "Expected: $SYSTEM_PROMPT_SRC"
fi

# Memory
if [[ -d "$MEMORY_SRC" ]]; then

    rm -rf "$NF_HERMES_HOME/memory"
    cp -R "$MEMORY_SRC" "$NF_HERMES_HOME/memory"

    success "NIGHTFANG memory installed."

else
    warn "No NIGHTFANG memory directory found."
fi

# ------------------------------------------------------------
# Install metadata
# ------------------------------------------------------------

cat > "$NF_HERMES_HOME/installation.json" <<EOF
{
  "name": "nightfang",
  "adapter": "hermes",
  "nightfang_root": "$NIGHTFANG_ROOT",
  "installed_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "skills": "$NF_SKILL_LINK",
  "system_context": "$NF_HERMES_HOME/system.md",
  "memory": "$NF_HERMES_HOME/memory"
}
EOF

success "Installation metadata created."

# ------------------------------------------------------------
# Create NIGHTFANG launcher helper
# ------------------------------------------------------------

cat > "$NF_HERMES_HOME/status.sh" <<EOF
#!/usr/bin/env bash

echo
echo "NIGHTFANG / Hermes"
echo "=================="
echo
echo "NIGHTFANG root : $NIGHTFANG_ROOT"
echo "Hermes home    : $HERMES_HOME"
echo "Skills         : $NF_SKILL_LINK"
echo "System context : $NF_HERMES_HOME/system.md"
echo "Memory         : $NF_HERMES_HOME/memory"
echo

if [[ -L "$NF_SKILL_LINK" ]]; then
    echo "[✓] Skills linked"
else
    echo "[✗] Skills not linked"
fi

if [[ -f "$NF_HERMES_HOME/system.md" ]]; then
    echo "[✓] System context installed"
else
    echo "[✗] System context missing"
fi

if [[ -d "$NF_HERMES_HOME/memory" ]]; then
    echo "[✓] Memory installed"
else
    echo "[!] Memory not installed"
fi

echo
EOF

chmod +x "$NF_HERMES_HOME/status.sh"

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

echo
echo "══════════════════════════════════════════════════"
success "NIGHTFANG Hermes adapter installed."
echo "══════════════════════════════════════════════════"
echo

echo "NIGHTFANG:"
echo "  $NIGHTFANG_ROOT"
echo

echo "Hermes:"
echo "  $HERMES_HOME"
echo

echo "Skills:"
echo "  $NF_SKILL_LINK"
echo

echo "Adapter:"
echo "  $NF_HERMES_HOME"
echo

echo "Run status:"
echo "  $NF_HERMES_HOME/status.sh"
echo

echo "Start Hermes normally:"
echo "  hermes"
echo

echo "NIGHTFANG is now available to Hermes."
echo
```