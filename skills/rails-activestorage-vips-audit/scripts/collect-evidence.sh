#!/bin/sh
# Collect static evidence for a CVE-2026-66066 (Active Storage / libvips) audit.
#
# This script gathers facts only. It intentionally contains no verdict logic:
# deciding exposure requires resolving variant_processor precedence and judging
# whether a mitigation is reachable at runtime, neither of which a grep can do.
#
# Usage: collect-evidence.sh <application-root> [application-root...]
#        collect-evidence.sh            # defaults to the current directory

set -u

scan_status=0
nested_app_roots=''

section() {
  printf '\n===== %s =====\n' "$1"
}

collection_error() {
  label=$1
  command_status=$2
  output=$3

  printf '(COLLECTION ERROR: %s; command exited %s)\n' "$label" "$command_status"
  if [ -n "$output" ]; then
    printf '%s\n' "$output"
  fi
  scan_status=1
}

# Print matches, an explicit "none", or an explicit collection error. A grep
# exit status of 1 means no match; anything higher means the audit did not
# inspect all of the evidence and must fail closed.
report() {
  label=$1
  shift
  out=$("$@" 2>&1)
  command_status=$?

  case $command_status in
    0)
      if [ -n "$out" ]; then
        printf '%s\n' "$out"
      else
        printf '(none found: %s)\n' "$label"
      fi
      ;;
    1)
      printf '(none found: %s)\n' "$label"
      ;;
    *)
      collection_error "$label" "$command_status" "$out"
      ;;
  esac
}

# find with vendored third-party code pruned at any depth — matches there
# describe dependencies rather than this application's own configuration.
# The patterns stay quoted inside this function so the shell cannot glob them.
pruned_find() {
  find_output=$(find . \( -path '*/node_modules' -o -path '*/vendor/bundle' -o -path '*/.git' -o -path '*/tmp' \) -prune -o "$@" 2>&1)
  find_status=$?
  if [ "$find_status" -ne 0 ]; then
    printf '%s\n' "$find_output" >&2
    return 2
  fi

  if [ -z "$nested_app_roots" ]; then
    printf '%s\n' "$find_output"
    return
  fi

  printf '%s\n' "$find_output" | while IFS= read -r path; do
    include_path=1
    while IFS= read -r nested_root; do
      case "$path" in
        "$nested_root"|"$nested_root"/*)
          include_path=0
          break
          ;;
      esac
    done <<EOF
$nested_app_roots
EOF
    [ "$include_path" -eq 1 ] && printf '%s\n' "$path"
  done
  return 0
}

# Files that reach libvips without going through Active Storage. This decides
# nothing about the CVE, and is collected because a reader who sees no libvips
# evidence at all concludes libvips is irrelevant to the application.
# The pattern deliberately excludes bare `Vips.<method>`: it would match
# Vips.block_untrusted, the mitigation this skill tells fix mode to write, and
# report the operator's own remediation as an out-of-scope exposure.
# shellcheck disable=SC2329,SC2317  # invoked indirectly, through report_capped "$@"
grep_direct_vips() {
  direct_vips_status=0
  for vglob in '*.rb' '*.rake'; do
    grep_repo "$vglob" 'Vips::Image|ImageProcessing::Vips' || direct_vips_status=2
  done
  return "$direct_vips_status"
}

# Like report(), but truncated: a section that can match hundreds of unrelated
# lines buries the few that decide anything. The total is printed so the reader
# knows the list was cut rather than exhausted.
report_capped() {
  limit=$1
  label=$2
  shift 2
  out=$("$@" 2>&1)
  command_status=$?

  case $command_status in
    0)
      ;;
    1)
      printf '(none found: %s)\n' "$label"
      return
      ;;
    *)
      collection_error "$label" "$command_status" "$out"
      return
      ;;
  esac
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
  files=$(pruned_find -type f -name "$1" -print 2>&1)
  find_status=$?
  if [ "$find_status" -ne 0 ]; then
    printf '%s\n' "$files" >&2
    return 2
  fi
  [ -n "$files" ] || return 0

  grep_status=0
  while IFS= read -r f; do
    matches=$(grep -nE "$2" "$f" 2>&1)
    match_status=$?
    case $match_status in
      0)
        while IFS= read -r match; do
          printf '%s:%s\n' "$f" "$match"
        done <<EOF
$matches
EOF
        ;;
      1)
        ;;
      *)
        printf '%s\n' "$matches" >&2
        grep_status=2
        ;;
    esac
  done <<EOF
$files
EOF
  return "$grep_status"
}

# ERB, Haml, and Slim all render the same form helpers; searching only ERB
# misses Haml and Slim applications entirely.
# shellcheck disable=SC2329,SC2317  # invoked indirectly, through report "$@"
grep_templates() {
  template_status=0
  for tglob in '*.erb' '*.haml' '*.slim'; do
    grep_repo "$tglob" "$1" || template_status=2
  done
  return "$template_status"
}

# shellcheck disable=SC2329,SC2317  # invoked indirectly, through report "$@"
grep_container_definitions() {
  container_status=0
  for cglob in 'Dockerfile*' '*.Dockerfile' 'docker-compose*.yml' \
    'docker-compose*.yaml' 'compose*.yml' 'compose*.yaml'; do
    grep_repo "$cglob" "$1" || container_status=2
  done
  return "$container_status"
}

# shellcheck disable=SC2329,SC2317  # invoked indirectly, through report "$@"
grep_dockerfiles() {
  dockerfile_status=0
  for dglob in 'Dockerfile*' '*.Dockerfile'; do
    grep_repo "$dglob" "$1" || dockerfile_status=2
  done
  return "$dockerfile_status"
}

# shellcheck disable=SC2329,SC2317  # invoked indirectly, through report "$@"
grep_javascript() {
  javascript_status=0
  for jglob in '*.js' '*.mjs' '*.jsx' '*.ts' '*.tsx' '*.vue' '*.svelte'; do
    grep_repo "$jglob" "$1" || javascript_status=2
  done
  return "$javascript_status"
}

# Search the source and template file types that can contain a controller
# parameter or form field. This goes through grep_repo so nested application
# boundaries and collection failures are handled exactly like every other
# evidence search.
# shellcheck disable=SC2329,SC2317  # invoked indirectly, through report "$@"
grep_attachment_reference() {
  reference_status=0
  for rglob in '*.rb' '*.erb' '*.haml' '*.slim'; do
    grep_repo "$rglob" "$1" || reference_status=2
  done
  return "$reference_status"
}

# shellcheck disable=SC2329,SC2317  # invoked indirectly and directly
grep_attachment_declarations() {
  declarations=$(grep_repo '*.rb' 'has_(one|many)_attached' 2>&1)
  declaration_status=$?
  if [ "$declaration_status" -ne 0 ]; then
    printf '%s\n' "$declarations" >&2
    return 2
  fi
  printf '%s\n' "$declarations" | sed -E '/:[0-9]+:[[:space:]]*#/d'
}

scan_one() {
  scan_status=0
  nested_app_roots=''
  printf '\n################################################################\n'
  printf '# APPLICATION ROOT: %s\n' "$(pwd)"
  printf '################################################################\n'

  if [ ! -f Gemfile ] && [ ! -f Gemfile.lock ]; then
    collection_error 'no Gemfile or Gemfile.lock at this application root' 2 \
      'Pass each Rails application directory separately; do not audit a monorepo root as one application.'
    return "$scan_status"
  fi

  all_locks=$(pruned_find -type f -name Gemfile.lock -print 2>&1)
  lock_find_status=$?
  if [ "$lock_find_status" -ne 0 ]; then
    collection_error 'discovering Gemfile.lock files' "$lock_find_status" "$all_locks"
    return "$scan_status"
  fi
  nested_locks=$(printf '%s\n' "$all_locks" | sed -e '/^\.\/Gemfile\.lock$/d' -e '/^$/d')
  nested_support_roots=''
  while IFS= read -r nested_lock; do
    [ -n "$nested_lock" ] || continue
    candidate_root=${nested_lock%/Gemfile.lock}
    if [ -f "$candidate_root/config/application.rb" ]; then
      if [ -n "$nested_app_roots" ]; then
        nested_app_roots="$nested_app_roots
$candidate_root"
      else
        nested_app_roots=$candidate_root
      fi
    elif [ -n "$nested_support_roots" ]; then
      nested_support_roots="$nested_support_roots
$candidate_root"
    else
      nested_support_roots=$candidate_root
    fi
  done <<EOF
$nested_locks
EOF
  if [ -n "$nested_app_roots" ]; then
    printf 'Nested Rails application roots are excluded from this evidence stream:\n'
    printf '%s\n' "$nested_app_roots"
    printf 'Pass each one separately to audit it.\n'
  fi
  if [ -n "$nested_support_roots" ]; then
    printf 'Nested lockfile roots without config/application.rb remain in scope:\n'
    printf '%s\n' "$nested_support_roots"
    printf 'They may be mounted engines or path dependencies; inspect how the host loads them.\n'
  fi

  section "1. Resolved gem versions (Gemfile.lock is authoritative)"
  if [ ! -f Gemfile.lock ]; then
    printf '(none found: Gemfile.lock — resolved versions are unknowable here;\n'
    printf ' Gemfile constraints are not versions, so the version condition is undetermined)\n'
  else
    printf -- '--- ./Gemfile.lock\n'
    report 'no activestorage/rails/vips gems in ./Gemfile.lock' \
      grep -nE '^ +(activestorage|rails|ruby-vips|image_processing|mini_magick) \([0-9]' ./Gemfile.lock
  fi

  section "2. Active Storage use (correlate strong and supporting evidence)"
  printf 'Engine loading, storage.yml, and generated tables show availability, not use.\n'
  printf 'Confirm use from an attachment declaration or Active Storage API call.\n'
  report 'config/storage.yml (supporting only)' pruned_find -type f -name storage.yml -print
  report 'active_storage tables in Ruby migrations/schema' grep_repo '*.rb' 'active_storage_(blobs|attachments|variant_records)'
  report 'active_storage tables in structure.sql' grep_repo '*.sql' 'active_storage_(blobs|attachments|variant_records)'
  report 'has_one_attached / has_many_attached' grep_attachment_declarations
  report 'qualified Active Storage API calls' \
    grep_repo '*.rb' 'ActiveStorage::(Blob|Attachment)'
  report 'attachment API candidates (correlate the receiver)' \
    grep_repo '*.rb' '\.(attach|purge|purge_later)[( ]'
  report 'engine require in application.rb (supporting only)' grep_repo 'application.rb' 'require ["'"'"'](rails/all|active_storage/engine)'

  section "3. variant_processor: explicit configuration"
  report 'explicit variant_processor assignment' grep_repo '*.rb' 'active_storage\.variant_processor'
  report 'variant_processor in YAML config' grep_repo '*.yml' 'variant_processor'

  section "4. variant_processor: load_defaults assignments (>= 7.0 writes :vips)"
  report 'config.load_defaults' grep_repo '*.rb' 'load_defaults'

  section "5. variant_processor: new_framework_defaults files"
  printf 'Rails ships these lines commented out. A leading # means the line does NOT apply.\n'
  nfd_files=$(pruned_find -type f -name 'new_framework_defaults*.rb' -print 2>&1)
  nfd_status=$?
  if [ "$nfd_status" -ne 0 ]; then
    collection_error 'new_framework_defaults files' "$nfd_status" "$nfd_files"
  elif [ -z "$nfd_files" ]; then
    printf '(none found: new_framework_defaults*.rb files)\n'
  else
    while IFS= read -r f; do
      printf -- '--- %s\n' "$f"
      report "no variant_processor line in $f" grep -nE 'variant_processor' "$f"
    done <<EOF
$nfd_files
EOF
  fi

  section "6. Mitigations (evidence only; none of these prove runtime behaviour)"
  report 'Vips.block_untrusted' grep_repo '*.rb' 'block_untrusted'
  report 'VIPS_BLOCK_UNTRUSTED' grep_repo '*' 'VIPS_BLOCK_UNTRUSTED'
  report 'libvips in container definitions' grep_container_definitions \
    'libvips|vips-dev|vips-tools'
  report 'base images (libvips version follows from the distro release)' \
    grep_dockerfiles '^ *FROM '

  section "7. Upload exposure"
  report 'direct upload (bypasses controller strong parameters)' grep_repo '*.rb' 'direct_upload|rails_direct_uploads'
  report 'direct upload in JS' grep_javascript 'DirectUpload|direct_upload'
  report 'file_field candidates (confirm the field names an attachment)' grep_templates 'file_field'
  # permit! names no attributes, so the name-targeted search below cannot see
  # it. It is a candidate until the controller is correlated with a model that
  # declares an attachment. Anchoring on "!" excludes permit_all_parameters.
  report 'permit! candidates (confirm the parameters reach an attachment model)' \
    grep_repo '*.rb' '\.permit!'

  # Search by the attachment names this application actually declares. A fixed
  # keyword list misses :resume or :logo, and dumping every permit line buries
  # the signal in a large application; deriving the names does neither.
  # sed -n keeps only lines it could parse: a declaration whose name is not a
  # symbol literal must not leak through as garbage that corrupts the grep
  # patterns built from it below.
  raw_attachment_decls=$(grep_attachment_declarations 2>&1)
  attachment_status=$?
  if [ "$attachment_status" -ne 0 ]; then
    collection_error 'attachment declarations' "$attachment_status" "$raw_attachment_decls"
    attachment_decls=''
  else
    attachment_decls=$(printf '%s\n' "$raw_attachment_decls" |
      sed -E '/:[0-9]+:[[:space:]]*#/d')
  fi
  names=$(printf '%s\n' "$attachment_decls" |
    sed -nE 's/.*has_(one|many)_attached[[:space:]]*\(?[[:space:]]*:([a-zA-Z0-9_]+).*/\2/p' |
    sort -u)
  unparsed=$(printf '%s\n' "$attachment_decls" |
    grep -vE 'has_(one|many)_attached[[:space:]]*\(?[[:space:]]*:[a-zA-Z0-9_]+')
  if [ -n "$unparsed" ]; then
    printf 'Declarations with no symbol-literal name (dynamic; resolve by hand):\n'
    printf '%s\n' "$unparsed"
  fi
  if [ -n "$names" ]; then
    printf 'Declared attachment names: %s\n' "$(printf '%s\n' "$names" | tr '\n' ' ')"
    # Both Ruby spellings of a parameter: the symbol form (:photos) and the
    # hash-label form (photos: []), which is how has_many_attached attributes
    # are permitted.
    for n in $names; do
      report "no candidate reference to declared attachment :$n" \
        grep_attachment_reference \
        "[:\"']${n}([^a-zA-Z0-9_]|\$)|(^|[^a-zA-Z0-9_])${n}[[:space:]]*:"
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
  if [ ! -f Gemfile.lock ]; then
    printf '(none found: Gemfile.lock, so authentication gems are not resolvable)\n'
  else
    printf -- '--- ./Gemfile.lock\n'
    report 'no authentication gems in ./Gemfile.lock' \
      grep -nE '^ +(devise|pundit|cancancan|rodauth|warden|clearance|omniauth) \(' ./Gemfile.lock
  fi

  section "9. libvips reached outside Active Storage (context only, never the verdict)"
  printf 'CVE-2026-66066 concerns Active Storage variant processing. Code handing\n'
  printf 'input straight to libvips reaches the same unsafe operations without\n'
  printf 'touching Active Storage, so it can be exposed even where the processor\n'
  printf 'resolves to :mini_magick and the verdict is NOT AFFECTED. The patched\n'
  printf 'activestorage blocks those operations process-wide, which is why the\n'
  printf 'upgrade still matters here. Report alongside the verdict, never inside it.\n'
  report_capped 15 'direct libvips calls' grep_direct_vips

  section "10. Remediation targets (NOT verdict inputs)"
  printf 'Constraints from Gemfile, not resolved versions. Section 1 remains the only\n'
  printf 'input to the version condition; these lines are what a fix edits, and a\n'
  printf 'constraint that pins below the patched release is why bundle update fails.\n'
  report_capped 15 'gem constraint lines in Gemfile' \
    grep_repo 'Gemfile' "^[[:space:]]*gem [\"'](rails|activestorage|ruby-vips|image_processing|mini_magick)[\"']"

  return "$scan_status"
}

[ "$#" -eq 0 ] && set -- .

status=0
for root in "$@"; do
  if [ ! -d "$root" ]; then
    printf '\n# SKIPPED (not a directory): %s\n' "$root" >&2
    status=1
    continue
  fi
  # Subshell so each application's cd and scan status cannot leak into the next.
  if ! (cd "$root" && scan_one); then
    status=1
  fi
done

printf '\nEvidence collection complete for %s application path(s).\n' "$#"
printf 'The runtime libvips version is NOT in this output and cannot be read from a\n'
printf 'repository. Confirm it where the app runs: vips --version (needs >= 8.13).\n'
printf 'Apply the SKILL.md decision steps to interpret this evidence.\n'
exit $status
