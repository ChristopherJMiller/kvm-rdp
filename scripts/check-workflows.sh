#!/usr/bin/env bash
# The rules CI's workflows keep (Plan E Task 2.1; spec §12's carries). CI
# runs this against itself in the `lint` job; scripts/test-check-workflows.sh
# is its test. The threat model is honest mistakes and drift: a malicious PR
# runs its own copy of this script, so fork-PR safety is GitHub's read-only
# token plus owner review. Workflow structure is read with yq (flow style,
# quoted keys and `uses :` all parse the same), never with line greps. Every
# yq or grep reads a variable, never a pipe a `grep -q` could cut short:
# under pipefail a SIGPIPE'd writer would make a match read as no match.
#  1. Every `uses:` anywhere in a workflow names its action by a full commit
#     SHA with its tag in a comment; local (`./`) actions and job-level
#     `uses:` (reusable workflows) and `secrets:` are refused.
#  2. A workflow's triggers are only push, pull_request, schedule and
#     workflow_dispatch (an allowlist: issue_comment and kin run fork code
#     with the default branch's ref and cache scope).
#  3. Each workflow's top-level permissions are exactly `contents: read`.
#  4. A job that asks for any write permission (`write`, `write-all`) runs
#     only on a push to main: its `if:` is exactly GUARD below.
#  5. Every image the Dockerfile names (FROM, an ARG default that is an image,
#     COPY --from=, RUN --mount=...from=) carries a digest, stages excepted.
#  6. scripts/image-build.sh assigns BUILDKIT_IMAGE by digest, at least once,
#     and names no literal `image=` driver option.
#  7. Every job has `timeout-minutes`.
#  8. Every Swatinem/rust-cache step saves only on main: its `save-if` is
#     `${{ github.ref == 'refs/heads/main' }}` or `false`.
#  9. `secrets` (as an identifier, any case, in a `${{ }}` or an `if:`) appears
#     only in a job that keeps rule 4's guard, never outside a job.
# 10. Every actions/checkout step sets `persist-credentials: false`.
# (yq's `//` treats `false` as absent, so rules 8 and 10 read the bare value:
# an absent key prints `null`.)
# 11. One repository, one SHA, across every workflow.
# Action names are matched lower-cased: GitHub resolves owner/repo without case.
set -euo pipefail
wf=${WORKFLOWS_DIR:-.github/workflows}
dockerfile=${DOCKERFILE:-Dockerfile}
image_build=${IMAGE_BUILD:-scripts/image-build.sh}
fail=0
err() { echo "check-workflows: $*" >&2; fail=1; }
digest='@sha256:[0-9a-f]{64}'
guard="github.event_name == 'push' && github.ref == 'refs/heads/main'"
# shellcheck disable=SC2016  # GitHub's literal ${{ }}
main_only='${{ github.ref == '"'refs/heads/main'"' }}'
secret_re='(^|[^A-Za-z0-9_.-])secrets([^A-Za-z0-9_-]|$)'
trim() { local s=$1; s=${s#"${s%%[![:space:]]*}"}; printf '%s' "${s%"${s##*[![:space:]]}"}"; }
# Whether job $2 of workflow $1 runs only on a push to main (rule 4's guard,
# with any `${{ }}` around it stripped).
guarded() {
  local c
  c=$(yq ".jobs.\"$2\".if // \"\"" "$1")
  c=$(trim "$c")
  c=${c#\$\{\{}
  c=${c%\}\}}
  [ "$(trim "$c")" = "$guard" ]
}
# Whether the YAML subtree on stdin... (as text $1) names `secrets` in an
# expression: inside a ${{ }} or as an if: value (rule 9).
mentions_secrets() { # $1 = file, $2 = yq path of the subtree
  local strs exprs ifs
  strs=$(yq -r "$2 | .. | select(tag == \"!!str\")" "$1")
  exprs=$(grep -oE '\$\{\{([^}]|\}[^}])*\}\}' <<<"$strs" || true)
  ifs=$(yq -r "$2 | .. | select(tag == \"!!map\") | select(has(\"if\")) | .if | select(tag == \"!!str\")" "$1")
  grep -Eiq "$secret_re" <<<"$exprs"$'\n'"$ifs"
}
pins=
shopt -s nullglob
for f in "$wf"/*.yml "$wf"/*.yaml; do
  # Rule 1: every uses anywhere in the tree, with the comment beside it.
  while IFS=$'\t' read -r ref comment; do
    [ -n "$ref" ] || continue  # yq prints one empty row when nothing matches
    ref=$(printf '%s' "$ref" | tr '[:upper:]' '[:lower:]')
    comment=$(trim "${comment#"${comment%%[!#[:space:]]*}"}")
    if ! grep -qE '^[a-z0-9_.-]+/[a-z0-9_./-]+@[0-9a-f]{40}$' <<<"$ref" ||
      ! grep -qE '^[vV]?[0-9]' <<<"$comment"; then
      err "$f: not a commit SHA with its tag in a comment (local and docker:// actions are refused too): $ref # $comment"
    else
      pins+="$(cut -d/ -f1-2 <<<"${ref%%@*}")@${ref##*@}"$'\n'
    fi
  done < <(yq -r '.. | select(tag == "!!map") | select(has("uses")) | .uses | select(tag == "!!str") | [., line_comment] | @tsv' "$f")
  # Rule 2: the trigger allowlist.
  while IFS= read -r ev; do
    case $ev in
      push|pull_request|schedule|workflow_dispatch) ;;
      *) err "$f: trigger '$ev' is not one of push, pull_request, schedule, workflow_dispatch" ;;
    esac
  done < <(yq -r '.on | ((select(tag == "!!map") | keys) // (select(tag == "!!seq")) // [.]) | .[]' "$f")
  top=$(yq -o=json -I=0 '.permissions' "$f")
  [ "$top" = '{"contents":"read"}' ] || err "$f: top-level permissions must be exactly contents: read (got $top)"
  outside=$(yq -o=json -I=0 'del(.jobs)' "$f")
  if grep -Eiq "$secret_re" <<<"$(grep -oE '\$\{\{([^}]|\}[^}])*\}\}' <<<"$outside" || true)" ||
    grep -Eiq '"[^"]*secrets\.' <<<"$outside"; then
    err "$f: secrets outside a job (every job would read it)"
  fi
  for job in $(yq '.jobs | keys | .[]' "$f"); do
    # m3: no reusable-workflow call, no inherited secrets.
    if [ "$(yq ".jobs.\"$job\" | has(\"uses\") or has(\"secrets\")" "$f")" = true ]; then
      err "$f: job $job has a job-level uses: or secrets: (reusable workflows are not allowed)"
    fi
    perms=$(yq -o=json -I=0 ".jobs.\"$job\".permissions // {}" "$f")
    if grep -qE '"write(-all)?"' <<<"$perms" && ! guarded "$f" "$job"; then
      err "$f: job $job asks for write permissions but its if: is not exactly: $guard"
    fi
    timeout=$(yq ".jobs.\"$job\".\"timeout-minutes\" // \"\"" "$f")
    [ -n "$timeout" ] || err "$f: job $job has no timeout-minutes"
    if mentions_secrets "$f" ".jobs.\"$job\"" && ! guarded "$f" "$job"; then
      err "$f: job $job reads a secret but does not run only on a push to main"
    fi
    while IFS= read -r v; do
      [ "$v" = "$main_only" ] || [ "$v" = false ] ||
        err "$f: job $job: a rust-cache step must save only on main (save-if: $v)"
    done < <(yq ".jobs.\"$job\".steps[]? | select((.uses // \"\") | downcase | test(\"^swatinem/rust-cache@\")) | .with.\"save-if\"" "$f")
    while IFS= read -r v; do
      [ "$v" = false ] || err "$f: job $job: a checkout must set persist-credentials: false (got $v)"
    done < <(yq ".jobs.\"$job\".steps[]? | select((.uses // \"\") | downcase | test(\"^actions/checkout@\")) | .with.\"persist-credentials\"" "$f")
  done
done
twice=$(printf '%s' "$pins" | LC_ALL=C sort -u | cut -d@ -f1 | uniq -d)
[ -z "$twice" ] || err "one action pinned to two SHAs: $(tr '\n' ' ' <<<"$twice")"

# Rule 5: the Dockerfile, normalised (continuations joined, indentation
# stripped, instructions case-insensitive, --flags skipped, quotes dropped).
declare -A argdef=()
declare -A stage=()
image_ok() { # $1 = a reference, $2 = the instruction for the message
  local img=$1 sub name val
  # Substitute $VAR and ${VAR} from the ARG defaults.
  while [[ $img =~ \$\{?([A-Za-z_][A-Za-z0-9_]*)\}? ]]; do
    name=${BASH_REMATCH[1]}
    if [ -z "${argdef[$name]+x}" ] || [ -z "${argdef[$name]}" ]; then
      err "$dockerfile: ARG $name has no default but names an image: $2"
      return 0
    fi
    val=${argdef[$name]}
    sub=${BASH_REMATCH[0]}
    img=${img/"$sub"/$val}
  done
  img=$(printf '%s' "$img" | tr '[:upper:]' '[:lower:]' | tr -d "\"'")
  case $img in scratch) return 0 ;; esac
  [ -z "${stage[$img]+x}" ] || return 0
  [[ $img =~ ^[0-9]+$ ]] && return 0
  grep -qE "$digest" <<<"$img" || err "$dockerfile: image not pinned by digest: $2"
}
if [ -f "$dockerfile" ]; then
  norm=$(awk '
    { sub(/^[ \t]+/, ""); if ($0 ~ /^#/) next
      buf = cont ? buf " " $0 : $0
      if (buf ~ /\\[ \t]*$/) { sub(/\\[ \t]*$/, "", buf); cont = 1 } else { print buf; cont = 0; buf = "" } }
    END { if (cont) print buf }' "$dockerfile")
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    instr=$(awk '{print tolower($1)}' <<<"$line")
    rest=${line#* }
    case $instr in
      arg)
        name=${rest%%=*}; name=$(trim "$name")
        if [[ $rest == *=* ]]; then
          val=${rest#*=}; val=$(trim "$val"); val=${val//\"/}; val=${val//\'/}
          argdef[$name]=$val
          # An ARG default that is itself an image (name:tag, with or without a registry).
          if [[ $val != *://* ]] && grep -qE '^[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+(@.*)?$' <<<"$val" &&
            ! grep -qE "$digest" <<<"$val"; then
            err "$dockerfile: image ARG not pinned by digest: $line"
          fi
        else
          argdef[$name]=""
        fi
        ;;
      from)
        img=
        as=
        set -f
        # shellcheck disable=SC2086  # word splitting is the point
        set -- $rest
        set +f
        while [ $# -gt 0 ]; do
          case $1 in
            --*) ;;
            *) if [ -z "$img" ]; then img=$1
               elif [ "$(tr '[:upper:]' '[:lower:]' <<<"$1")" = as ] && [ $# -ge 2 ]; then as=$2; break; fi ;;
          esac
          shift
        done
        [ -n "$img" ] || { err "$dockerfile: FROM names no image: $line"; continue; }
        image_ok "$img" "$line"
        [ -z "$as" ] || stage[$(tr '[:upper:]' '[:lower:]' <<<"$as")]=1
        ;;
      copy|add|run)
        for ref in $(grep -oiE '(--from=|[,[:space:]]from=)[^,[:space:]]+' <<<"$line" | sed -E 's/^.*from=//I' || true); do
          image_ok "$ref" "$line"
        done
        ;;
    esac
  done <<<"$norm"
fi
# Rule 6: the BuildKit image.
if [ -f "$image_build" ]; then
  assigns=$(grep -E '^[[:space:]]*((export|readonly|local|declare)[[:space:]]+)?BUILDKIT_IMAGE=' "$image_build" || true)
  [ -n "$assigns" ] || err "$image_build: no BUILDKIT_IMAGE assignment (the BuildKit image must be named, by digest)"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    grep -qE "$digest" <<<"$line" || err "$image_build: BuildKit image not pinned by digest: $line"
  done <<<"$assigns"
  if grep -qE 'image=[^$[:space:]"'"'"']' "$image_build"; then
    err "$image_build: a literal image= driver option (use \$BUILDKIT_IMAGE)"
  fi
fi
[ "$fail" -eq 0 ] && echo "check-workflows: every rule holds"
exit "$fail"
