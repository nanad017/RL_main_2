#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "recreate_env_no_dataset.sh is kept for compatibility; using setup_rl_env.sh."
exec "$ROOT_DIR/scripts/setup_rl_env.sh" "$@"
