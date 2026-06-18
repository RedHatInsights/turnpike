#!/usr/bin/env bash
set -euo pipefail

msg_file="$1"

if grep -qiP '^Co-Authored-By:\s.*(claude|anthropic|noreply@anthropic)' "$msg_file"; then
  echo "REJECTED: Commit contains AI co-author trailer."
  echo "Remove the Co-Authored-By line and try again."
  exit 1
fi

if grep -qiP '^\S*Generated with \[?Claude' "$msg_file"; then
  echo "REJECTED: Commit contains AI branding line."
  echo "Remove the 'Generated with Claude' line and try again."
  exit 1
fi
