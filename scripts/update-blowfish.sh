#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/update-blowfish.sh [options] <target-ref>

Update the Blowfish submodule to a specific tag/branch/commit and replay local fixes.

Defaults:
  --submodule-path themes/blowfish
  --fix-branch     upstream-main-with-local-fixes
  --fix-base       upstream/main

Options:
  -s, --submodule-path <path>   Submodule directory path.
  -b, --fix-branch <ref>        Branch containing your local fixes.
      --fix-base <ref>          Base ref used to identify fix commits.
      --no-fetch                Skip fetch --all --tags --prune.
  -n, --dry-run                 Show actions without changing anything.
  -h, --help                    Show this help text.

Examples:
  scripts/update-blowfish.sh v2.92.0
  scripts/update-blowfish.sh upstream/main
  scripts/update-blowfish.sh -n origin/main
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '%s\n' "$*"
}

require_clean_submodule() {
  local path="$1"

  if ! git -C "$path" diff --quiet || ! git -C "$path" diff --cached --quiet; then
    die "submodule has uncommitted changes: $path"
  fi

  if [[ -n "$(git -C "$path" ls-files --others --exclude-standard)" ]]; then
    die "submodule has untracked files: $path"
  fi
}

resolve_commit() {
  local repo_path="$1"
  local ref="$2"

  git -C "$repo_path" rev-parse --verify --quiet "${ref}^{commit}"
}

submodule_path="themes/blowfish"
fix_branch="upstream-main-with-local-fixes"
fix_base="upstream/main"
skip_fetch=0
dry_run=0
target_ref=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -s|--submodule-path)
      [[ $# -ge 2 ]] || die "missing value for $1"
      submodule_path="$2"
      shift 2
      ;;
    -b|--fix-branch)
      [[ $# -ge 2 ]] || die "missing value for $1"
      fix_branch="$2"
      shift 2
      ;;
    --fix-base)
      [[ $# -ge 2 ]] || die "missing value for $1"
      fix_base="$2"
      shift 2
      ;;
    --no-fetch)
      skip_fetch=1
      shift
      ;;
    -n|--dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      die "unknown option: $1"
      ;;
    *)
      if [[ -z "$target_ref" ]]; then
        target_ref="$1"
      else
        die "unexpected extra argument: $1"
      fi
      shift
      ;;
  esac
done

[[ -n "$target_ref" ]] || {
  usage >&2
  exit 1
}

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || die "run this from inside the blog git repository"
submodule_dir="$repo_root/$submodule_path"

git -C "$submodule_dir" rev-parse --git-dir >/dev/null 2>&1 \
  || die "submodule is missing or not initialized at: $submodule_path"

require_clean_submodule "$submodule_dir"

if [[ "$skip_fetch" -eq 0 ]]; then
  log "Fetching remotes in $submodule_path ..."
  git -C "$submodule_dir" fetch --all --tags --prune
fi

resolve_commit "$submodule_dir" "$fix_branch" >/dev/null \
  || die "cannot resolve fix branch: $fix_branch"
resolve_commit "$submodule_dir" "$fix_base" >/dev/null \
  || die "cannot resolve fix base: $fix_base"
target_commit="$(resolve_commit "$submodule_dir" "$target_ref")" \
  || die "cannot resolve target ref: $target_ref"

mapfile -t fix_commits < <(git -C "$submodule_dir" rev-list --reverse --no-merges "${fix_base}..${fix_branch}")

log "Target ref: $target_ref"
log "Target commit: ${target_commit:0:12}"
log "Fix branch: $fix_branch"
log "Fix base: $fix_base"
log "Fix commits to replay: ${#fix_commits[@]}"

for commit in "${fix_commits[@]}"; do
  log "  - $(git -C "$submodule_dir" show -s --format='%h %s' "$commit")"
done

if [[ "$dry_run" -eq 1 ]]; then
  log "Dry run complete. No changes were made."
  exit 0
fi

log "Resetting $fix_branch to target commit ..."
git -C "$submodule_dir" checkout -B "$fix_branch" "$target_commit"

for commit in "${fix_commits[@]}"; do
  marker="$(git -C "$submodule_dir" cherry HEAD "$commit" | awk '{print $1}')"
  if [[ "$marker" == "-" ]]; then
    log "Skipping already-applied fix: $(git -C "$submodule_dir" show -s --format='%h %s' "$commit")"
    continue
  fi

  log "Cherry-picking: $(git -C "$submodule_dir" show -s --format='%h %s' "$commit")"
  if ! git -C "$submodule_dir" cherry-pick -x "$commit"; then
    printf '\n' >&2
    printf 'Cherry-pick failed. Resolve conflicts in %s and continue manually:\n' "$submodule_path" >&2
    printf '  git -C %s cherry-pick --continue\n' "$submodule_path" >&2
    printf 'Or abort:\n' >&2
    printf '  git -C %s cherry-pick --abort\n' "$submodule_path" >&2
    exit 1
  fi
done

new_head="$(git -C "$submodule_dir" rev-parse --short HEAD)"
log "Done. $submodule_path now points to $new_head on branch $fix_branch."
log "Next:"
log "  git add $submodule_path"
log "  git commit -m \"chore(blowfish): update to $target_ref with local fixes\""
