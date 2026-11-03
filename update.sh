#!/usr/bin/env bash
set -Eeuo pipefail

# Safe updater for hehebacon/auto-find-bug.
# Preserves tracked and untracked local changes; never runs reset, clean, or force operations.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "${SCRIPT_DIR}/.git" ]]; then
  REPO_DIR="${SCRIPT_DIR}"
elif [[ -d "${SCRIPT_DIR}/auto-find-bug/.git" ]]; then
  REPO_DIR="${SCRIPT_DIR}/auto-find-bug"
else
  printf '[ERROR] Cannot locate the auto-find-bug Git repository.\n' >&2
  exit 1
fi

PYTHON="${PYTHON:-python3}"
BRANCH="main"
STASH_CREATED=0
STASH_REF=""

info() { printf '[INFO] %s\n' "$*"; }
ok()   { printf '[ OK ] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
fail() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

cd "$REPO_DIR"

command -v git >/dev/null 2>&1 || fail "Git is required."
command -v "$PYTHON" >/dev/null 2>&1 || fail "Python executable not found: $PYTHON"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "Not a Git worktree."
git remote get-url origin >/dev/null 2>&1 || fail "Remote 'origin' is not configured."

CURRENT_BRANCH="$(git branch --show-current)"
[[ "$CURRENT_BRANCH" == "$BRANCH" ]] || fail "Expected branch '$BRANCH', found '$CURRENT_BRANCH'. Switch branches manually; updater will not change branches."

PY_VERSION="$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)' || fail "Python 3.11 or newer is required."

restore_stash() {
  if [[ "$STASH_CREATED" -eq 1 ]]; then
    info "Restoring local changes from $STASH_REF ..."
    if git stash apply --index "$STASH_REF"; then
      ok "Local changes restored. Backup remains in git stash."
      STASH_CREATED=0
    else
      warn "Could not fully restore local changes. Resolve conflicts manually; backup remains at $STASH_REF."
      exit 2
    fi
  fi
}

on_error() {
  local status=$?
  trap - ERR
  if [[ "$STASH_CREATED" -eq 1 ]]; then
    restore_stash || true
  fi
  exit "$status"
}
trap on_error ERR

if [[ -n "$(git status --porcelain)" ]]; then
  info "Saving tracked and untracked local changes before syncing..."
  git stash push --include-untracked -m "auto-find-bug updater backup $(date -Is)"
  STASH_REF="stash@{0}"
  STASH_CREATED=1
  ok "Local changes backed up in Git stash."
else
  info "Working tree is clean."
fi

info "Fetching latest refs from origin..."
git fetch --prune origin

LOCAL_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git rev-parse "origin/$BRANCH")"
BASE_SHA="$(git merge-base HEAD "origin/$BRANCH")"

if [[ "$LOCAL_SHA" != "$REMOTE_SHA" ]]; then
  if [[ "$BASE_SHA" == "$LOCAL_SHA" ]]; then
    info "Fast-forwarding to origin/$BRANCH..."
    git merge --ff-only "origin/$BRANCH"
  elif [[ "$BASE_SHA" == "$REMOTE_SHA" ]]; then
    restore_stash
    fail "Local branch is ahead of origin. Push or reconcile it manually; updater will not overwrite commits."
  else
    restore_stash
    fail "Local and remote branches have diverged. Reconcile manually; updater will not rewrite history."
  fi
else
  ok "Repository code is already up to date."
fi

restore_stash

info "Creating/updating project virtual environment..."
if [[ ! -x ".venv/bin/python" ]]; then
  "$PYTHON" -m venv .venv
fi
VENV_PYTHON=".venv/bin/python"
VENV_PIP=".venv/bin/pip"
[[ -x "$VENV_PYTHON" && -x "$VENV_PIP" ]] || fail "Virtual environment is incomplete."

info "Updating pip, setuptools, wheel and project dependencies..."
"$VENV_PYTHON" -m pip install --upgrade pip setuptools wheel
"$VENV_PYTHON" -m pip install --upgrade --editable .

info "Compiling source and tests..."
"$VENV_PYTHON" -m compileall -q src tests

info "Checking CLI entry points..."
"$VENV_PYTHON" -m auto_find_bug --help >/dev/null
".venv/bin/auto-find-bug" --help >/dev/null

info "Running unit tests..."
"$VENV_PYTHON" -m unittest discover -s tests -v

trap - ERR
ok "Update and validation completed."
printf '\nRepository: %s\nBranch:     %s\nCommit:     %s\nPython:     %s\n' \
  "$REPO_DIR" "$BRANCH" "$(git rev-parse --short HEAD)" "$PY_VERSION"
printf 'Local files, caches and run.sh were not cleaned or deleted.\n'
printf 'Any stash backup is intentionally retained for recovery.\n'
