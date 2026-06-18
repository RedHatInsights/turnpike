#!/usr/bin/env bash
# Invariant: No AI/Claude co-author references in commits
set -euo pipefail

WORKTREE_DIR="${1:-.}"
BASE_BRANCH="${2:-master}"

commits=$(git -C "$WORKTREE_DIR" log --format="%H %s%n%b" "origin/$BASE_BRANCH..HEAD" 2>/dev/null || true)
[[ -z "$commits" ]] && exit 0

violations=$(echo "$commits" | grep -iP '^Co-Authored-By:\s.*(claude|anthropic|noreply@anthropic)|^\S*Generated with \[?Claude' || true)

if [[ -n "$violations" ]]; then
  echo "FAIL: AI co-author references found in commits:"
  echo "$violations"
  exit 1
fi
exit 0
