#!/usr/bin/env bash
# ─── OWASP Guardian — Tiered Workflow Launcher ───────────────────────────────
# Single command to run the full Tier 1 → Tier 2 pipeline
#
# Usage:
#   ./guardian-workflow.sh [target] [options]
#
# Examples:
#   ./guardian-workflow.sh .
#   ./guardian-workflow.sh ~/projects/myapp --min-severity high
#   ./guardian-workflow.sh ./src --window 30 --out-dir /tmp/guardian
#   ./guardian-workflow.sh . --only-tier1
#   ./guardian-workflow.sh . --min-severity critical --no-open

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_BIN="$(which node 2>/dev/null || echo '')"

# ── Check Node.js ─────────────────────────────────────────────────────────────
if [ -z "$NODE_BIN" ]; then
  echo "❌  Node.js is required but not found. Install from https://nodejs.org"
  exit 1
fi

NODE_VERSION=$("$NODE_BIN" -e "process.stdout.write(process.version.slice(1).split('.')[0])")
if [ "$NODE_VERSION" -lt 16 ]; then
  echo "❌  Node.js 16+ required (found v$NODE_VERSION)"
  exit 1
fi

# ── Pass all args to the workflow orchestrator ────────────────────────────────
exec "$NODE_BIN" "$SCRIPT_DIR/cli/workflow.js" "$@"
