#!/bin/sh
# Collect static evidence for a CVE-2026-66066 (Active Storage / libvips) audit.
#
# This script gathers facts only. It intentionally contains no verdict logic:
# deciding exposure requires resolving variant_processor precedence and judging
# whether a mitigation is reachable at runtime, neither of which a grep can do.
#
# Usage: collect-evidence.sh <repo-root> [repo-root...]
#        collect-evidence.sh            # defaults to the current directory

set -u

section() {
  printf '\n===== %s =====\n' "$1"
}

# Print matches, or an explicit "none" so an empty section is never mistaken
# for a section that failed to run.
report() {
  label=$1
  shift
  out=$("$@" 2>/dev/null)
  if [ -n "$out" ]; then
    printf '%s\n' "$out"
  else
    printf '(none found: %s)\n' "$label"
  fi
}

# find with vendored third-party code pruned at any depth — matches there
# describe dependencies rather than this application's own configuration.
# The patterns stay quoted inside this function so the shell cannot glob them.
pruned_find() {
  find . \( -path '*/node_modules' -o -path '*/vendor/bundle' -o -path '*/.git' -o -path '*/tmp' \) -prune -o "$@" 2>/dev/null
}

# Files that reach libvips without going through Active Storage. This decides
# nothing about the CVE, and is collected because a reader who sees no libvips
# evidence at all concludes libvips is irrelevant to the application.
# shellcheck disable=SC2329,SC2317  # invoked indirectly, through report_capped "$@"
grep_direct_vips() {
  grep -rInE --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=vendor \
    --include='*.rb' --include='*.rake' \
    'Vips::Image|ImageProcessing::Vips|Vips\.[a-z_]+' .
}

# Like report(), but truncated: a section that can match hundreds of unrelated
# lines buries the few that decide anything. The total is printed so the reader
# knows the list was cut rather than exhausted.
report_capped() {
  limit=$1
  label=$2
  shift 2
  out=$("$@" 2>/dev/null)
  if [ -z "$out" ]; then
    printf '(none found: %s)\n' "$label"
    return
  fi
  total=$(printf '%s\n' "$out" | wc -l | tr -d ' ')
  printf '%s\n' "$out" | head -n "$limit"
  if [ "$total" -gt "$limit" ]; then
    printf '(showing %s of %s matches; open the repository if this section decides the verdict)\n' \
      "$limit" "$total"
  fi
}

grep_repo() {
  pruned_find -type f -name "$1" -print | while IFS= read -r f; do
    grep -nE "$2" "$f" 2>/dev/null | sed "s|^|$f:|"
  done
}

# ERB, Haml, and Slim all render the same form helpers; searching only ERB
# misses Haml and Slim applications entirely.
# shellcheck disable=SC2329,SC2317  # invoked indirectly, through report "$@"
grep_templates() {
  for tglob in '*.erb' '*.haml' '*.slim'; do
    grep_repo "$tglob" "$1"
  done
}

scan_one() {
  printf '\n################################################################\n'
  printf '# REPOSITORY: %s\n' "$(pwd)"
  printf '################################################################\n'

  if [ ! -f Gemfile ] && [ ! -f Gemfile.lock ]; then
    printf 'No Gemfile or Gemfile.lock at this root. Not a Ruby application root,\n'
    printf 'or the application lives in a subdirectory. Locate it before judging.\n'
  fi

  section "1. Resolved gem versions (Gemfile.lock is authoritative)"
  locks=$(pruned_find -type f -name Gemfile.lock -print)
  if [ -z "$locks" ]; then
    printf '(none found: Gemfile.lock — resolved versions are unknowable here;\n'
    printf ' Gemfile constraints are not versions, so the version condition is undetermined)\n'
  else
    printf '%s\n' "$locks" | while IFS= read -r lock; do
      printf -- '--- %s\n' "$lock"
      report "no activestorage/rails/vips gems in $lock" \
        grep -nE '^ +(activestorage|rails|ruby-vips|image_processing|mini_magick) \([0-9]' "$lock"
    done
  fi

  section "2. Active Storage in use"
  report 'config/storage.yml' pruned_find -type f -name storage.yml -print
  report 'active_storage tables in Ruby migrations/schema' grep_repo '*.rb' 'active_storage_(blobs|attachments|variant_records)'
  report 'active_storage tables in structure.sql' grep_repo '*.sql' 'active_storage_(blobs|attachments|variant_records)'
  report 'has_one_attached / has_many_attached' grep_repo '*.rb' 'has_(one|many)_attached'
  report 'engine require in application.rb' grep_repo 'application.rb' 'require ["'"'"'](rails/all|active_storage/engine)'

  section "3. variant_processor: explicit configuration"
  report 'explicit variant_processor assignment' grep_repo '*.rb' 'active_storage\.variant_processor'
  report 'variant_processor in YAML config' grep_repo '*.yml' 'variant_processor'

  section "4. variant_processor: load_defaults fallback (>= 7.0 resolves to :vips)"
  report 'config.load_defaults' grep_repo '*.rb' 'load_defaults'

  section "5. variant_processor: new_framework_defaults files"
  printf 'Rails ships these lines commented out. A leading # means the line does NOT apply.\n'
  nfd_files=$(pruned_find -type f -name 'new_framework_defaults*.rb' -print)
  if [ -z "$nfd_files" ]; then
    printf '(none found: new_framework_defaults*.rb files)\n'
  else
    printf '%s\n' "$nfd_files" | while IFS= read -r f; do
      printf -- '--- %s\n' "$f"
      report "no variant_processor line in $f" grep -nE 'variant_processor' "$f"
    done
  fi

  section "6. Mitigations (evidence only; none of these prove runtime behaviour)"
  report 'Vips.block_untrusted' grep_repo '*.rb' 'block_untrusted'
  report 'VIPS_BLOCK_UNTRUSTED' \
    grep -rInE --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=vendor 'VIPS_BLOCK_UNTRUSTED' .
  report 'libvips in container definitions' \
    grep -rInE --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=vendor \
      'libvips|vips-dev|vips-tools' ./Dockerfile* ./docker-compose*.yml ./*.Dockerfile
  report 'base images (libvips version follows from the distro release)' \
    grep -rInE --exclude-dir=node_modules --exclude-dir=.git '^ *FROM ' ./Dockerfile* ./*.Dockerfile

  section "7. Upload exposure"
  report 'direct upload (bypasses controller strong parameters)' grep_repo '*.rb' 'direct_upload|rails_direct_uploads'
  report 'direct upload in JS' \
    grep -rInE --exclude-dir=node_modules --exclude-dir=.git \
      --include='*.js' --include='*.mjs' --include='*.jsx' --include='*.ts' --include='*.tsx' \
      --include='*.vue' --include='*.svelte' \
      'DirectUpload|direct_upload' .
  report 'file_field form helpers' grep_templates 'file_field'
  # permit! names no attributes, so the name-targeted search below cannot see it
  # even though it permits the attachment and is the strongest evidence there is.
  # Anchoring on the "!" excludes permit_all_parameters, a config setter.
  report 'permit! (permits every attribute, attachments included)' grep_repo '*.rb' '\.permit!'

  # Search by the attachment names this application actually declares. A fixed
  # keyword list misses :resume or :logo, and dumping every permit line buries
  # the signal in a large application; deriving the names does neither.
  # sed -n keeps only lines it could parse: a declaration whose name is not a
  # symbol literal must not leak through as garbage that corrupts the grep
  # patterns built from it below.
  attachment_decls=$(grep_repo '*.rb' 'has_(one|many)_attached')
  names=$(printf '%s\n' "$attachment_decls" |
    sed -nE 's/.*has_(one|many)_attached[[:space:]]*\(?[[:space:]]*:([a-zA-Z0-9_]+).*/\2/p' |
    sort -u)
  unparsed=$(printf '%s\n' "$attachment_decls" |
    grep -vE 'has_(one|many)_attached[[:space:]]*\(?[[:space:]]*:[a-zA-Z0-9_]+')
  if [ -n "$unparsed" ]; then
    printf 'Declarations with no symbol-literal name (dynamic or commented; resolve by hand):\n'
    printf '%s\n' "$unparsed"
  fi
  if [ -n "$names" ]; then
    printf 'Declared attachment names: %s\n' "$(printf '%s\n' "$names" | tr '\n' ' ')"
    # Both Ruby spellings of a parameter: the symbol form (:photos) and the
    # hash-label form (photos: []), which is how has_many_attached attributes
    # are permitted.
    for n in $names; do
      report "no reference to :$n" \
        grep -rInE --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=vendor \
          --include='*.rb' --include='*.erb' --include='*.haml' --include='*.slim' \
          "[:\"']${n}([^a-zA-Z0-9_]|\$)|(^|[^a-zA-Z0-9_])${n}[[:space:]]*:" .
    done
  else
    printf 'No has_one_attached / has_many_attached symbol-literal declarations found;\n'
    printf 'falling back to strong-parameter calls, read against section 2. None of\n'
    printf 'these decide anything on their own, so the list is capped.\n'
    report_capped 15 'strong parameters and params.expect' \
      grep_repo '*.rb' '\.permit[(! ]|params\.expect[( ]'
  fi

  section "8. Authentication hints (affects severity, not the verdict)"
  printf 'These greps can only confirm authentication, never rule it out: route\n'
  printf 'constraints, rack middleware, and filters inherited from a parent class\n'
  printf 'outside this repository are all invisible here.\n'
  # `authorize` is anchored to the start of a statement; an unanchored match
  # would hit comments and unrelated calls, and a false positive here is worse
  # than a miss because the audit rule trusts positives.
  report 'authentication filters' grep_repo '*.rb' \
    'before_action :(authenticate|require_login|require_user)|authenticate_user!|authenticate_admin!|verify_authorized|policy_scope|^[[:space:]]*authorize[( ]'
  if [ -z "$locks" ]; then
    printf '(none found: Gemfile.lock, so authentication gems are not resolvable)\n'
  else
    printf '%s\n' "$locks" | while IFS= read -r lock; do
      printf -- '--- %s\n' "$lock"
      report "no authentication gems in $lock" \
        grep -nE '^ +(devise|pundit|cancancan|rodauth|warden|clearance|omniauth) \(' "$lock"
    done
  fi

  section "9. libvips reached outside Active Storage (context only, never the verdict)"
  printf 'CVE-2026-66066 concerns Active Storage variant processing. Code handing\n'
  printf 'input straight to libvips is a separate exposure sharing the same unsafe\n'
  printf 'operations, and upgrading activestorage does not necessarily cover it.\n'
  printf 'Report these alongside the verdict, never inside it.\n'
  report_capped 15 'direct libvips calls' grep_direct_vips
}

[ "$#" -eq 0 ] && set -- .

status=0
for root in "$@"; do
  if [ ! -d "$root" ]; then
    printf '\n# SKIPPED (not a directory): %s\n' "$root" >&2
    status=1
    continue
  fi
  # Subshell so each repository's cd cannot leak into the next iteration.
  (cd "$root" && scan_one)
done

printf '\nEvidence collection complete for %s repository path(s).\n' "$#"
printf 'The runtime libvips version is NOT in this output and cannot be read from a\n'
printf 'repository. Confirm it where the app runs: vips --version (needs >= 8.13).\n'
printf 'Apply the SKILL.md decision steps to interpret this evidence.\n'
exit $status
