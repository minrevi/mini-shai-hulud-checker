#!/usr/bin/env bash

# Mini Shai-Hulud local scanner
# macOS / Linux
#
# Purpose:
#   Detect known local indicators of Mini Shai-Hulud / Shai-Hulud-like supply-chain compromise.
#
# Exit codes:
#   0 = GREEN: no known local IoC found
#   1 = RED: known infection indicators found
#   2 = YELLOW: suspicious/risky indicators found, human review needed
#
# This script is read-only.
# It does not delete files, stop processes, revoke tokens, install packages, or modify settings.

set -u

# -----------------------------
# Colors
# -----------------------------

if [ -t 1 ]; then
  C_RED="$(printf '\033[31m')"
  C_YELLOW="$(printf '\033[33m')"
  C_GREEN="$(printf '\033[32m')"
  C_BLUE="$(printf '\033[34m')"
  C_BOLD="$(printf '\033[1m')"
  C_RESET="$(printf '\033[0m')"
else
  C_RED=""
  C_YELLOW=""
  C_GREEN=""
  C_BLUE=""
  C_BOLD=""
  C_RESET=""
fi

# -----------------------------
# Report setup
# -----------------------------

HOST_SAFE="$(hostname 2>/dev/null | tr -c 'A-Za-z0-9._-' '_' | sed 's/_$//')"
REPORT="${PWD}/mini-shai-hulud-scan-${HOST_SAFE}-$(date +%Y%m%d-%H%M%S).log"

exec > >(tee "$REPORT") 2>&1

RED_HITS=()
YELLOW_HITS=()
INFO_HITS=()
PROJECT_CONFIG_REVIEW_HITS=()

add_red() {
  RED_HITS+=("$1")
  echo "${C_RED}[RED]${C_RESET} $1"
}

add_yellow() {
  YELLOW_HITS+=("$1")
  echo "${C_YELLOW}[YELLOW]${C_RESET} $1"
}

add_yellow_review() {
  local title="$1"
  local file="$2"
  local note="$3"

  YELLOW_HITS+=("${title}: ${file}")
  echo "${C_YELLOW}[YELLOW]${C_RESET} ${title}"
  echo "  ファイル: ${file}"
  echo "  補足: ${note}"
}

add_project_config_review_hit() {
  local file="$1"
  local matches="$2"

  PROJECT_CONFIG_REVIEW_HITS+=("${file}|${matches}")
}

flush_project_config_review_hits() {
  local hit file matches

  [ "${#PROJECT_CONFIG_REVIEW_HITS[@]}" -gt 0 ] || return

  YELLOW_HITS+=("レビュー対象（感染確定ではありません）: プロジェクト設定に実行系パターンがあります: ${#PROJECT_CONFIG_REVIEW_HITS[@]}件")
  echo "${C_YELLOW}[YELLOW]${C_RESET} レビュー対象（感染確定ではありません）: プロジェクト設定に実行系パターンがあります"
  echo "  件数: ${#PROJECT_CONFIG_REVIEW_HITS[@]}件"
  echo "  補足: 開発用の自動処理設定では通常でも検出されることがあります。この結果だけでは感染確定ではありません。"
  echo "  確認: 自分で削除や変更をせず、このレポートを担当者へ共有してください。"
  echo "  ファイル:"

  for hit in "${PROJECT_CONFIG_REVIEW_HITS[@]}"; do
    file="${hit%%|*}"
    matches="${hit#*|}"
    echo "    - $file"
    echo "      一致: $matches"
  done
}

add_info() {
  INFO_HITS+=("$1")
  echo "${C_BLUE}[INFO]${C_RESET} $1"
}

section() {
  echo
  echo "${C_BOLD}=== $1 ===${C_RESET}"
}

exists_cmd() {
  command -v "$1" >/dev/null 2>&1
}

dedupe_roots() {
  local seen="|"
  local out=()
  local r abs

  for r in "$@"; do
    [ -d "$r" ] || continue
    abs="$(cd "$r" 2>/dev/null && pwd -P)" || continue

    case "$seen" in
    *"|$abs|"*) ;;
    *)
      seen="${seen}${abs}|"
      out+=("$abs")
      ;;
    esac
  done

  printf '%s\n' "${out[@]}"
}

print_matches_only() {
  local pattern="$1"
  local file="$2"

  grep -Eo "$pattern" "$file" 2>/dev/null |
    sed 's/[[:space:]]*$//' |
    sort -u |
    head -30 |
    sed 's/^/  一致: /' ||
    true
}

is_ai_or_editor_config_file() {
  local f="$1"

  case "$f" in
  */.claude/*) return 0 ;;
  */.vscode/*) return 0 ;;
  */.github/workflows/*.yml) return 0 ;;
  */.github/workflows/*.yaml) return 0 ;;
  */.mcp.json) return 0 ;;
  */mcp.json) return 0 ;;
  */Library/Application\ Support/Code/User/*) return 0 ;;
  */Library/Application\ Support/Cursor/User/*) return 0 ;;
  */Library/Application\ Support/Windsurf/User/*) return 0 ;;
  */.config/Code/User/*) return 0 ;;
  */.config/Cursor/User/*) return 0 ;;
  */.config/Windsurf/User/*) return 0 ;;
  *) return 1 ;;
  esac
}

is_dependency_payload_file() {
  local f="$1"

  case "$f" in
  */node_modules/*) return 0 ;;
  */vendor/*) return 0 ;;
  *) return 1 ;;
  esac
}

is_github_workflow_file() {
  local f="$1"

  case "$f" in
  */.github/workflows/*.yml) return 0 ;;
  */.github/workflows/*.yaml) return 0 ;;
  *) return 1 ;;
  esac
}

# -----------------------------
# Scan roots
# -----------------------------
# If arguments are passed, scan those directories.
# Otherwise scan common developer directories plus current directory.

ROOTS=()

if [ "$#" -gt 0 ]; then
  while IFS= read -r r; do
    ROOTS+=("$r")
  done < <(dedupe_roots "$@")
else
  CANDIDATES=(
    "$PWD"
    "$HOME/dev"
    "$HOME/src"
    "$HOME/work"
    "$HOME/projects"
    "$HOME/repos"
    "$HOME/workspace"
    "$HOME/ghq"
    "$HOME/code"
    "$HOME/company"
    "$HOME/Documents"
    "$HOME/Git"
  )

  while IFS= read -r r; do
    ROOTS+=("$r")
  done < <(dedupe_roots "${CANDIDATES[@]}")
fi

# -----------------------------
# IoC patterns
# -----------------------------

# Strong IoCs.
# These are RED because they indicate known campaign artifacts,
# known persistence, known exfil domains, or known malicious dependency patterns.
STRONG_IOC_PATTERN='A Mini Shai-Hulud has Appeared|filev2[.]getsession[.]org|seed[123][.]getsession[.]org|api[.]masscan[.]cloud|git-tanstack[.]com|gh-token-monitor|router_init[.]js|tanstack_runner[.]js|bun_environment[.]js|setup_bun[.]js|@tanstack/setup|github:tanstack/router|79ac49eedf774dd4b0cfa308722bc463cfe5885c'

# Risky package scopes / names.
# These are YELLOW because legitimate projects may use these packages safely.
# Presence means "review exact package/version/install timing", not "infected".
RISKY_PACKAGE_PATTERN='@tanstack/|@uipath/|@mistralai/|@squawk/|@tallyui/|@beproduct/|@draftlab/|@draftauth/|@taskflow-corp/|@tolka/|@opensearch-project/|guardrails-ai|intercom-client|@sap/cds|@sap/cds-dk|(^|[^A-Za-z0-9_-])lightning([^A-Za-z0-9_-]|$)'

# Config review patterns.
# Keep broad/common CI terms as INFO-level context; YELLOW is reserved for
# executable hooks, direct script execution, shell downloads, or known attacker
# file names. This reduces noise from normal GitHub Actions and notifications.
CONFIG_INFO_PATTERN='Notification|command[[:space:]]*:|npm[[:space:]]|yarn[[:space:]]'
CONFIG_REVIEW_PATTERN='SessionStart|PreToolUse|PostToolUse|Stop|SubagentStop|UserPromptSubmit|settings[.]local[.]json|setup[.]mjs|router_runtime[.]js|curl[[:space:]]|wget[[:space:]]|bash[[:space:]]+-c|sh[[:space:]]+-c|node[[:space:]].*[.](mjs|js)|python3?[[:space:]]|npx[[:space:]]|pnpm[[:space:]]|uvx[[:space:]]|pipx[[:space:]]|base64[[:space:]]|gh[[:space:]]+auth|GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY|AWS_SECRET_ACCESS_KEY|AZURE_|GOOGLE_APPLICATION_CREDENTIALS'

# Suspicious process / command-line indicators.
PROC_PATTERN='gh-token-monitor|router_init[.]js|tanstack_runner[.]js|bun_environment[.]js|setup_bun[.]js|filev2[.]getsession[.]org|seed[123][.]getsession[.]org|api[.]masscan[.]cloud|git-tanstack[.]com'

# File names that should generally not exist in normal projects.
SUSPICIOUS_FILE_NAME_PATTERN='router_init[.]js|tanstack_runner[.]js|bun_environment[.]js|setup_bun[.]js'

# -----------------------------
# Header
# -----------------------------

echo "${C_BOLD}Mini Shai-Hulud ローカルスキャン${C_RESET}"
echo "開始日時: $(date)"
echo "ホスト: ${HOST_SAFE}"
echo "ユーザー: ${USER:-unknown}"
echo "レポート: ${REPORT}"
echo

if [ "${#ROOTS[@]}" -eq 0 ]; then
  add_yellow "スキャン対象ディレクトリが見つかりませんでした。例: ./mini-shai-hulud-scan.sh ~/dev ~/work ~/workspace ~/ghq のように明示してください"
fi

section "スキャン対象"
for r in "${ROOTS[@]}"; do
  echo "- $r"
done

# -----------------------------
# 1. Process check
# -----------------------------

section "1. 実行中プロセスの確認"

PROC_HITS="$(
  ps -axo pid=,command= 2>/dev/null |
    grep -E "$PROC_PATTERN" |
    grep -v -E 'grep|mini-shai-hulud-scan[.]sh' ||
    true
)"

if [ -n "$PROC_HITS" ]; then
  add_red "不審な実行中プロセスまたはコマンドラインが見つかりました"
  echo "$PROC_HITS"
else
  add_info "不審な実行中プロセスは見つかりませんでした"
fi

# -----------------------------
# 2. OS persistence check
# -----------------------------

section "2. OS 永続化設定の確認"

OS_PERSISTENCE_HITS=0

# macOS LaunchAgent known path
MAC_LAUNCH_AGENT="$HOME/Library/LaunchAgents/com.user.gh-token-monitor.plist"

if [ -f "$MAC_LAUNCH_AGENT" ]; then
  OS_PERSISTENCE_HITS=$((OS_PERSISTENCE_HITS + 1))
  add_red "既知の不審な macOS LaunchAgent が存在します: $MAC_LAUNCH_AGENT"
fi

# macOS LaunchAgents generic check
if [ -d "$HOME/Library/LaunchAgents" ]; then
  while IFS= read -r f; do
    OS_PERSISTENCE_HITS=$((OS_PERSISTENCE_HITS + 1))
    add_red "不審な LaunchAgent ファイルが見つかりました: $f"
  done < <(
    find "$HOME/Library/LaunchAgents" \
      -type f \
      \( -iname '*gh-token-monitor*' -o -iname '*shai*' -o -iname '*hulud*' \) \
      -print 2>/dev/null
  )

  while IFS= read -r f; do
    if grep -Eq "$STRONG_IOC_PATTERN" "$f" 2>/dev/null; then
      OS_PERSISTENCE_HITS=$((OS_PERSISTENCE_HITS + 1))
      add_red "LaunchAgent 内に強い IoC が見つかりました: $f"
      print_matches_only "$STRONG_IOC_PATTERN" "$f"
    fi
  done < <(
    find "$HOME/Library/LaunchAgents" -type f -name '*.plist' -print 2>/dev/null
  )
fi

# Linux systemd user service known path
LINUX_SYSTEMD_SERVICE="$HOME/.config/systemd/user/gh-token-monitor.service"

if [ -f "$LINUX_SYSTEMD_SERVICE" ]; then
  OS_PERSISTENCE_HITS=$((OS_PERSISTENCE_HITS + 1))
  add_red "既知の不審な systemd user service が存在します: $LINUX_SYSTEMD_SERVICE"
fi

# Linux systemd generic check
if [ -d "$HOME/.config/systemd/user" ]; then
  while IFS= read -r f; do
    OS_PERSISTENCE_HITS=$((OS_PERSISTENCE_HITS + 1))
    add_red "不審な systemd user ファイルが見つかりました: $f"
  done < <(
    find "$HOME/.config/systemd/user" \
      -type f \
      \( -iname '*gh-token-monitor*' -o -iname '*shai*' -o -iname '*hulud*' \) \
      -print 2>/dev/null
  )

  while IFS= read -r f; do
    if grep -Eq "$STRONG_IOC_PATTERN" "$f" 2>/dev/null; then
      OS_PERSISTENCE_HITS=$((OS_PERSISTENCE_HITS + 1))
      add_red "systemd user service 内に強い IoC が見つかりました: $f"
      print_matches_only "$STRONG_IOC_PATTERN" "$f"
    fi
  done < <(
    find "$HOME/.config/systemd/user" -type f -print 2>/dev/null
  )
fi

# Linux desktop autostart
if [ -d "$HOME/.config/autostart" ]; then
  while IFS= read -r f; do
    OS_PERSISTENCE_HITS=$((OS_PERSISTENCE_HITS + 1))
    add_red "不審な autostart ファイルが見つかりました: $f"
  done < <(
    find "$HOME/.config/autostart" \
      -type f \
      \( -iname '*gh-token-monitor*' -o -iname '*shai*' -o -iname '*hulud*' \) \
      -print 2>/dev/null
  )

  while IFS= read -r f; do
    if grep -Eq "$STRONG_IOC_PATTERN" "$f" 2>/dev/null; then
      OS_PERSISTENCE_HITS=$((OS_PERSISTENCE_HITS + 1))
      add_red "autostart エントリ内に強い IoC が見つかりました: $f"
      print_matches_only "$STRONG_IOC_PATTERN" "$f"
    fi
  done < <(
    find "$HOME/.config/autostart" -type f -print 2>/dev/null
  )
fi

# Generic gh-token-monitor path under ~/.config
if [ -d "$HOME/.config" ]; then
  while IFS= read -r f; do
    OS_PERSISTENCE_HITS=$((OS_PERSISTENCE_HITS + 1))
    add_red "不審な設定パスが見つかりました: $f"
  done < <(
    find "$HOME/.config" \
      \( -type f -o -type d \) \
      -iname '*gh-token-monitor*' \
      -print 2>/dev/null
  )
fi

if [ "$OS_PERSISTENCE_HITS" -eq 0 ]; then
  add_info "OS 永続化設定を確認しました。不審な LaunchAgent / systemd user service / autostart は見つかりませんでした"
fi

# -----------------------------
# 3. Suspicious file-name check
# -----------------------------

section "3. 不審なファイル名の確認"

SUSPICIOUS_FILE_NAME_HITS=0

for root in "${ROOTS[@]}"; do
  while IFS= read -r f; do
    SUSPICIOUS_FILE_NAME_HITS=$((SUSPICIOUS_FILE_NAME_HITS + 1))
    add_red "不審なファイル名が見つかりました: $f"
  done < <(
    find "$root" \
      \( \
      -path '*/.git' \
      -o -path '*/node_modules' \
      -o -path '*/.yarn/cache' \
      -o -path '*/.pnpm-store' \
      -o -path '*/.nuxt' \
      -o -path '*/dist' \
      -o -path '*/build' \
      -o -path '*/coverage' \
      -o -path '*/.Trash' \
      -o -path '*/Library' \
      -o -path '*/.cache' \
      \) -prune -o \
      -type f -print 2>/dev/null |
      grep -E "$SUSPICIOUS_FILE_NAME_PATTERN" ||
      true
  )
done

if [ "$SUSPICIOUS_FILE_NAME_HITS" -eq 0 ]; then
  add_info "不審なファイル名を確認しました。既知の不審ファイル名は見つかりませんでした"
fi

# -----------------------------
# 4. Global AI/editor config check
# -----------------------------

section "4. グローバル AI/エディタ設定の確認"

GLOBAL_CONFIG_FILES=(
  # Claude Code global/user config
  "$HOME/.claude/settings.json"
  "$HOME/.claude/settings.local.json"
  "$HOME/.claude.json"

  # macOS VS Code user config
  "$HOME/Library/Application Support/Code/User/settings.json"
  "$HOME/Library/Application Support/Code/User/tasks.json"
  "$HOME/Library/Application Support/Code/User/keybindings.json"

  # macOS Cursor user config
  "$HOME/Library/Application Support/Cursor/User/settings.json"
  "$HOME/Library/Application Support/Cursor/User/tasks.json"
  "$HOME/Library/Application Support/Cursor/User/keybindings.json"

  # macOS Windsurf user config
  "$HOME/Library/Application Support/Windsurf/User/settings.json"
  "$HOME/Library/Application Support/Windsurf/User/tasks.json"
  "$HOME/Library/Application Support/Windsurf/User/keybindings.json"

  # Linux VS Code user config
  "$HOME/.config/Code/User/settings.json"
  "$HOME/.config/Code/User/tasks.json"
  "$HOME/.config/Code/User/keybindings.json"

  # Linux Cursor user config
  "$HOME/.config/Cursor/User/settings.json"
  "$HOME/.config/Cursor/User/tasks.json"
  "$HOME/.config/Cursor/User/keybindings.json"

  # Linux Windsurf user config
  "$HOME/.config/Windsurf/User/settings.json"
  "$HOME/.config/Windsurf/User/tasks.json"
  "$HOME/.config/Windsurf/User/keybindings.json"

  # Known OS persistence paths
  "$HOME/.config/autostart/gh-token-monitor.desktop"
  "$HOME/.config/systemd/user/gh-token-monitor.service"
  "$HOME/Library/LaunchAgents/com.user.gh-token-monitor.plist"
)

for f in "${GLOBAL_CONFIG_FILES[@]}"; do
  [ -f "$f" ] || continue

  if grep -Eq "$STRONG_IOC_PATTERN" "$f" 2>/dev/null; then
    add_red "グローバル AI/エディタ/OS 設定に強い IoC が見つかりました: $f"
    print_matches_only "$STRONG_IOC_PATTERN" "$f"
    continue
  fi

  if grep -Eq "$CONFIG_REVIEW_PATTERN" "$f" 2>/dev/null; then
    add_yellow_review \
      "レビュー対象（感染確定ではありません）: グローバル AI/エディタ設定に実行系パターンがあります" \
      "$f" \
      "身に覚えがあり内容が想定通りなら、正常な設定の可能性が高いです。"
    print_matches_only "$CONFIG_REVIEW_PATTERN" "$f"
  elif grep -Eq "$CONFIG_INFO_PATTERN" "$f" 2>/dev/null; then
    add_info "グローバル設定に通常の実行/通知系パターンがあります（YELLOW対象外）: $f"
  else
    add_info "グローバル設定を確認しました: $f"
  fi
done

# -----------------------------
# 5. Project dependency/config file check
# -----------------------------

section "5. プロジェクト依存関係/設定ファイルの確認"

TARGET_FILE_FIND_EXPR=(
  # JS / TS dependency files
  -name 'package.json'
  -o -name 'package-lock.json'
  -o -name 'npm-shrinkwrap.json'
  -o -name 'pnpm-lock.yaml'
  -o -name 'yarn.lock'

  # Python dependency files
  -o -name 'pyproject.toml'
  -o -name 'poetry.lock'
  -o -name 'uv.lock'
  -o -name 'requirements.txt'
  -o -name 'requirements-*.txt'

  # Claude Code project configs
  -o -path '*/.claude/settings.json'
  -o -path '*/.claude/settings.local.json'
  -o -path '*/.claude/setup.mjs'
  -o -path '*/.claude/router_runtime.js'

  # MCP / agent configs
  -o -path '*/.mcp.json'
  -o -name 'mcp.json'

  # VS Code / Cursor / Windsurf workspace configs
  -o -path '*/.vscode/tasks.json'
  -o -path '*/.vscode/settings.json'
  -o -path '*/.vscode/launch.json'
  -o -path '*/.vscode/extensions.json'

  # GitHub workflow persistence / CI surface
  -o -path '*/.github/workflows/*.yml'
  -o -path '*/.github/workflows/*.yaml'
)

scan_file_for_iocs() {
  local file="$1"
  local matched=""
  local config_matched=""

  # Strong known IoCs
  if grep -Eq "$STRONG_IOC_PATTERN" "$file" 2>/dev/null; then
    add_red "ファイル内に強い IoC が見つかりました: $file"
    print_matches_only "$STRONG_IOC_PATTERN" "$file"
    return
  fi

  # Risky packages / scopes
  matched="$(grep -Eo "$RISKY_PACKAGE_PATTERN" "$file" 2>/dev/null | sed 's/[[:space:]]*$//' | sort -u | head -30 | tr '\n' ' ' || true)"
  if [ -n "$matched" ]; then
    add_yellow_review \
      "レビュー対象（感染確定ではありません）: リスク確認が必要な package scope/name があります" \
      "$file" \
      "正当利用の可能性もあるため、package 名・version・install 時刻を確認してください。"
    echo "  一致: $matched"
  fi

  # AI/editor/workflow configs with executable hooks/tasks/commands
  if is_ai_or_editor_config_file "$file"; then
    if is_dependency_payload_file "$file" && is_github_workflow_file "$file"; then
      return
    fi

    config_matched="$(grep -Eo "$CONFIG_REVIEW_PATTERN" "$file" 2>/dev/null | sed 's/[[:space:]]*$//' | sort -u | head -30 | tr '\n' ',' | sed 's/,$//; s/,/, /g' || true)"
    if [ -n "$config_matched" ]; then
      add_project_config_review_hit "$file" "$config_matched"
    elif grep -Eq "$CONFIG_INFO_PATTERN" "$file" 2>/dev/null; then
      add_info "プロジェクト設定に通常の実行/通知系パターンがあります（YELLOW対象外）: $file"
    fi
  fi
}

for root in "${ROOTS[@]}"; do
  while IFS= read -r -d '' f; do
    scan_file_for_iocs "$f"
  done < <(
    find "$root" \
      \( \
      -path '*/.git' \
      -o -path '*/node_modules' \
      -o -path '*/.yarn/cache' \
      -o -path '*/.pnpm-store' \
      -o -path '*/.nuxt' \
      -o -path '*/dist' \
      -o -path '*/build' \
      -o -path '*/coverage' \
      -o -path '*/.Trash' \
      -o -path '*/Library' \
      -o -path '*/.cache' \
      \) -prune -o \
      -type f \( "${TARGET_FILE_FIND_EXPR[@]}" \) -print0 2>/dev/null
  )
done

flush_project_config_review_hits

# -----------------------------
# 6. Shell history hint
# -----------------------------
# This is only a hint. Shell history often has no reliable timestamp.

section "6. シェル履歴のヒント"

HISTORY_FILES=(
  "$HOME/.zsh_history"
  "$HOME/.bash_history"
  "$HOME/.config/fish/fish_history"
)

HISTORY_PATTERN='npm[[:space:]]+(install|i|ci|update)|yarn[[:space:]]+(install|add|up|upgrade)|pnpm[[:space:]]+(install|add|update)|pip3?[[:space:]]+install|uv[[:space:]]+(pip[[:space:]]+install|sync|add)|poetry[[:space:]]+(install|add|update)'

for hf in "${HISTORY_FILES[@]}"; do
  [ -f "$hf" ] || continue

  count="$(grep -E "$HISTORY_PATTERN" "$hf" 2>/dev/null | tail -50 | wc -l | tr -d ' ')"

  if [ "${count:-0}" -gt 0 ]; then
    add_info "シェル履歴に依存関係の install/update コマンドが見つかりました: $hf"
    echo "  直近の一致コマンド（タイムスタンプは取得できない場合があります）:"
    grep -E "$HISTORY_PATTERN" "$hf" 2>/dev/null | tail -10 | sed 's/^/  /'
  else
    add_info "シェル履歴に明らかな依存関係の install/update コマンドは見つかりませんでした: $hf"
  fi
done

# -----------------------------
# 7. safe-chain installation status
# -----------------------------

section "7. safe-chain の導入状況"

if exists_cmd safe-chain; then
  add_info "safe-chain コマンドはインストールされています: $(command -v safe-chain)"
else
  add_info "safe-chain コマンドは見つかりませんでした。感染の証拠ではありませんが、install 時の保護として導入を推奨します。"
fi

if exists_cmd npm; then
  NPM_PATH="$(command -v npm)"
  echo "npm のパス: $NPM_PATH"
  case "$NPM_PATH" in
  *safe-chain*) add_info "npm は safe-chain shim 経由に見えます" ;;
  *) add_info "npm は safe-chain shim 経由ではないようです" ;;
  esac
fi

if exists_cmd yarn; then
  YARN_PATH="$(command -v yarn)"
  echo "yarn のパス: $YARN_PATH"
  case "$YARN_PATH" in
  *safe-chain*) add_info "yarn は safe-chain shim 経由に見えます" ;;
  *) add_info "yarn は safe-chain shim 経由ではないようです" ;;
  esac
fi

if exists_cmd pnpm; then
  PNPM_PATH="$(command -v pnpm)"
  echo "pnpm のパス: $PNPM_PATH"
  case "$PNPM_PATH" in
  *safe-chain*) add_info "pnpm は safe-chain shim 経由に見えます" ;;
  *) add_info "pnpm は safe-chain shim 経由ではないようです" ;;
  esac
fi

if exists_cmd pip; then
  PIP_PATH="$(command -v pip)"
  echo "pip のパス: $PIP_PATH"
  case "$PIP_PATH" in
  *safe-chain*) add_info "pip は safe-chain shim 経由に見えます" ;;
  *) add_info "pip は safe-chain shim 経由ではないようです" ;;
  esac
fi

if exists_cmd uv; then
  UV_PATH="$(command -v uv)"
  echo "uv のパス: $UV_PATH"
  case "$UV_PATH" in
  *safe-chain*) add_info "uv は safe-chain shim 経由に見えます" ;;
  *) add_info "uv は safe-chain shim 経由ではないようです" ;;
  esac
fi

# -----------------------------
# Summary
# -----------------------------

section "サマリ"

echo "RED 件数: ${#RED_HITS[@]}"
echo "YELLOW 件数: ${#YELLOW_HITS[@]}"
echo "レポート保存先: $REPORT"
echo

if [ "${#RED_HITS[@]}" -gt 0 ]; then
  echo "${C_RED}${C_BOLD}結果: RED - 既知の感染インジケータが見つかりました${C_RESET}"
  echo
  echo "推奨される次の対応:"
  echo "1. この端末をネットワークから切断してください。"
  echo "2. この端末から GitHub/npm/cloud トークンを失効しないでください。"
  echo "3. 証拠保全前に不審ファイルを削除しないでください。"
  echo "4. このレポートと不審ファイルを証拠として保存してください。"
  echo "5. セキュリティ/IT 担当へ連絡してください。"
  echo "6. 永続化の把握後、別の信頼できる端末から認証情報をローテーションしてください。"
  echo
  echo "RED 詳細:"
  for h in "${RED_HITS[@]}"; do
    echo "- $h"
  done
  exit 1
fi

if [ "${#YELLOW_HITS[@]}" -gt 0 ]; then
  detail_file=""
  detail_matches=""

  echo "${C_YELLOW}${C_BOLD}結果: YELLOW - 確認が必要な項目が見つかりました（感染確定ではありません）${C_RESET}"
  echo
  echo "報告:"
  echo "- この結果とレポート保存先を担当者へ報告してください。"
  echo "- 自分でファイル削除や設定変更をせず、担当者の確認を待ってください。"
  echo
  echo "補足:"
  echo "- YELLOW は感染確定ではありません。"
  echo "- 開発用の自動処理設定（GitHub Actions やエディタ設定）は、通常の設定でも検出されることがあります。"
  echo "- このスキャンでは、表示された設定が業務上正しいものかまでは確定できません。"
  echo
  echo "担当者確認用の詳細:"
  for h in "${YELLOW_HITS[@]}"; do
    echo "- $h"
  done
  if [ "${#PROJECT_CONFIG_REVIEW_HITS[@]}" -gt 0 ]; then
    echo "  プロジェクト設定の対象ファイル:"
    for h in "${PROJECT_CONFIG_REVIEW_HITS[@]}"; do
      detail_file="${h%%|*}"
      detail_matches="${h#*|}"
      echo "  - $detail_file"
      echo "    一致: $detail_matches"
    done
  fi
  exit 2
fi

echo "${C_GREEN}${C_BOLD}結果: GREEN - 既知の危険な痕跡は見つかりませんでした${C_RESET}"
echo
echo "報告:"
echo "- この結果とレポート保存先を担当者へ報告してください。"
echo
echo "注意:"
echo "- GREEN は、この端末上で既知の危険な痕跡が見つからなかったことを意味します。"
echo "- GREEN は、認証情報（ログイン情報やトークン等）が盗まれていないことの証明ではありません。"
echo "- このスキャンでは、2026-04-29 以降に依存関係の install/update があったか、またはこの端末が GitHub/npm/cloud などの重要な権限を持っているかは確定できません。該当する可能性がある場合は、担当者が別途確認してください。"
exit 0
