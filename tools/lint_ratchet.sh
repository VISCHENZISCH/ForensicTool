#!/usr/bin/env bash
# Cliquet de qualité : refuse toute hausse du nombre d'avertissements ruff (règles étendues :
# style, complexité, exceptions trop larges) et mypy par rapport au commit de base.
# Le stock existant n'est pas bloquant ; il ne peut que baisser.
#   usage : tools/lint_ratchet.sh <commit de base>
set -euo pipefail

base="${1:?commit de base requis}"
RUFF_RULES="E,W,F,B,BLE,C90,SIM,UP,PL"

count_ruff() {
  ruff check "$1/forensic_analyzer" --select "$RUFF_RULES" --exit-zero --no-cache \
       --output-format concise 2>/dev/null | grep -cE ':[0-9]+:[0-9]+: ' || true
}
count_mypy() {
  (cd "$1" && mypy forensic_analyzer --ignore-missing-imports --no-error-summary 2>/dev/null \
       | grep -c ': error:') || true
}

tmp="$(mktemp -d)"
trap 'git worktree remove --force "$tmp" >/dev/null 2>&1 || true' EXIT
git worktree add --quiet --detach "$tmp" "$base"

status=0
for tool in ruff mypy; do
  before="$("count_$tool" "$tmp")"
  after="$("count_$tool" .)"
  echo "$tool : $before avertissement(s) sur la base, $after maintenant"
  if [ "$after" -gt "$before" ]; then
    echo "::error::$tool : $((after - before)) nouvel(s) avertissement(s). Corriger avant de fusionner."
    status=1
  fi
done
exit "$status"
