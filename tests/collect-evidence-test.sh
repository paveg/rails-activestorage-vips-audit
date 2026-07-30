#!/bin/sh
# Regression tests for collect-evidence.sh. Each assertion pins a failure mode
# found in review: hash-label parameters missed, garbage attachment names,
# nested vendored directories leaking in, and silently empty sections.
set -u

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
subject=$script_dir/../skills/rails-activestorage-vips-audit/scripts/collect-evidence.sh

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
assert_contains() {
  if ! printf '%s\n' "$2" | grep -qF -- "$1"; then
    printf 'FAIL: output should contain: %s\n' "$1"
    fail=1
  fi
}
assert_not_contains() {
  if printf '%s\n' "$2" | grep -qF -- "$1"; then
    printf 'FAIL: output should NOT contain: %s\n' "$1"
    fail=1
  fi
}

app=$work/app
mkdir -p "$app/app/models" "$app/app/controllers" "$app/app/javascript" \
  "$app/app/views" "$app/config" \
  "$app/app/models/pipe|segment" \
  "$app/sub/node_modules/dep" "$app/engines/x/vendor/bundle/gems/dep"

cat > "$app/Gemfile" <<'EOF'
source "https://rubygems.org"
gem "rails", "~> 7.0.8"
gem "image_processing", "~> 1.12"
EOF

printf 'class OddPath < ApplicationRecord; has_one_attached :path_safe; end\n' \
  > "$app/app/models/pipe|segment/odd_path.rb"

cat > "$app/Gemfile.lock" <<'EOF'
GEM
  specs:
    activestorage (8.0.4)
      actionpack (= 8.0.4)
EOF

cat > "$app/app/models/user.rb" <<'EOF'
class User < ApplicationRecord
  has_many_attached :photos
  # has_one_attached is documented elsewhere
  # has_one_attached :commented_out
  %i[contract].each { |a| has_one_attached a }
end
EOF

cat > "$app/app/controllers/users_controller.rb" <<'EOF'
class UsersController < ApplicationController
  def user_params
    params.require(:user).permit(:name, photos: [])
  end
end
EOF

printf 'import { DirectUpload } from "@rails/activestorage"\n' > "$app/app/javascript/uploader.tsx"
printf '= f.file_field :photos\n' > "$app/app/views/form.html.haml"
printf 'has_one_attached :from_vendored_code\n' > "$app/sub/node_modules/dep/m.rb"
printf 'has_one_attached :from_vendored_code\n' > "$app/engines/x/vendor/bundle/gems/dep/m.rb"

mkdir -p "$work/nolock"
printf 'source "https://rubygems.org"\n' > "$work/nolock/Gemfile"

# libvips reached without Active Storage: out of CVE scope, but the same
# operations, so the evidence must surface it rather than drop it.
mkdir -p "$app/config/initializers"
cat > "$app/config/initializers/vips_block_untrusted.rb" <<'EOF'
require "vips"
if Vips.respond_to?(:block_untrusted)
  Vips.block_untrusted(true)
end
EOF

mkdir -p "$app/app/jobs"
cat > "$app/app/jobs/thumbnail_job.rb" <<'EOF'
class ThumbnailJob < ApplicationJob
  def perform(url)
    image = Vips::Image.new_from_file(download(url))
    ImageProcessing::Vips.source(image).resize_to_limit(64, 64).call
  end
end
EOF

# No attachment declarations, many unrelated permit calls: the fallback must
# stay readable instead of dumping every match.
mkdir -p "$work/nodecl/app/controllers"
printf 'GEM\n  specs:\n    activestorage (8.0.4)\n' > "$work/nodecl/Gemfile.lock"
{
  printf 'class WideController < ApplicationController\n'
  i=1
  while [ "$i" -le 30 ]; do
    printf '  def p%02d; params.require(:r).permit(:field_%02d); end\n' "$i" "$i"
    i=$((i + 1))
  done
  printf 'end\n'
} > "$work/nodecl/app/controllers/wide_controller.rb"

out=$(sh "$subject" "$app" "$work/nolock" "$work/nodecl")
out_status=$?
if [ "$out_status" -ne 0 ]; then
  printf 'FAIL: main evidence collection exited %s\n' "$out_status"
  fail=1
fi

# The hash-label strong parameter is how has_many_attached attributes are
# permitted; the :photos search must find it, not only the symbol form.
assert_contains 'permit(:name, photos: [])' "$out"

# Derived names are clean symbol literals only; unparseable declarations are
# surfaced for manual resolution instead of leaking through as regex garbage.
assert_contains 'Declared attachment names:' "$out"
assert_contains 'photos' "$out"
assert_contains 'path_safe' "$out"
assert_contains 'no symbol-literal name' "$out"
assert_not_contains 'no reference to :{' "$out"
section7=$(printf '%s\n' "$out" | sed -n '/7\. Upload exposure/,/^===== 8/p')
assert_not_contains 'commented_out' "$section7"
assert_not_contains 'commented_out' "$out"

# Valid path metacharacters must not be interpolated into a sed program and
# silently erase the evidence while the collector exits successfully.
assert_contains 'pipe|segment/odd_path.rb' "$out"
assert_contains 'has_one_attached :path_safe' "$out"
assert_not_contains 'bad flag in substitute command' "$out"

# Vendored third-party code stays out of the evidence at any depth.
assert_not_contains 'from_vendored_code' "$out"

# Non-ERB templates and JSX/TSX bundles are inside the search surface.
assert_contains 'uploader.tsx' "$out"
assert_contains 'form.html.haml' "$out"
assert_contains 'file_field candidates (confirm the field names an attachment)' "$out"

# A repository without a lockfile reports that, never a silent empty section.
assert_contains 'none found: Gemfile.lock' "$out"

# libvips reached outside Active Storage is out of scope for the verdict, but
# dropping it from the evidence lets a reader conclude libvips is irrelevant.
assert_contains 'Vips::Image.new_from_file' "$out"
assert_contains 'ImageProcessing::Vips.source' "$out"

# The Gemfile constraint is what remediation edits, and is never a verdict
# input; it has to be visible without being mistaken for a resolved version.
assert_contains 'Remediation targets (NOT verdict inputs)' "$out"
assert_contains 'gem "rails", "~> 7.0.8"' "$out"

# The no-declarations fallback stays readable: capped, with the total stated.
assert_contains 'field_01' "$out"
assert_contains 'showing 15 of 30' "$out"
assert_not_contains 'field_16' "$out"
assert_not_contains 'field_30' "$out"

# Section 9 is about libvips reached outside Active Storage. The mitigation
# initializer this skill itself tells fix mode to write is not that, and
# reporting it there would have the auditor flag their own remediation.
section9=$(printf '%s\n' "$out" | sed -n '/9\. libvips reached outside/,/^===== 10/p')
assert_not_contains 'block_untrusted' "$section9"

# A read error is not the same as an empty lockfile. The collector must fail
# closed so the agent cannot turn unreadable evidence into NOT AFFECTED.
mkdir -p "$work/unreadable"
printf 'GEM\n  specs:\n    activestorage (8.0.4)\n' > "$work/unreadable/Gemfile.lock"
chmod 000 "$work/unreadable/Gemfile.lock"
unreadable_out=$(sh "$subject" "$work/unreadable" 2>&1)
unreadable_status=$?
chmod 600 "$work/unreadable/Gemfile.lock"
if [ "$unreadable_status" -eq 0 ]; then
  printf 'FAIL: unreadable evidence should exit non-zero\n'
  fail=1
fi
assert_contains 'COLLECTION ERROR' "$unreadable_out"
assert_not_contains 'none found: no activestorage' "$unreadable_out"

# Errors inside the new-framework-defaults loop must propagate out of the
# current shell instead of being lost in a pipeline subshell.
mkdir -p "$work/unreadable/config/initializers"
nfd=$work/unreadable/config/initializers/new_framework_defaults_8_0.rb
printf 'Rails.application.config.active_storage.variant_processor = :vips\n' > "$nfd"
chmod 000 "$nfd"
nfd_out=$(sh "$subject" "$work/unreadable" 2>&1)
nfd_status=$?
chmod 600 "$nfd"
if [ "$nfd_status" -eq 0 ]; then
  printf 'FAIL: unreadable new_framework_defaults evidence should exit non-zero\n'
  fail=1
fi
assert_contains 'COLLECTION ERROR: no variant_processor line' "$nfd_out"

# A root and a nested application cannot share one evidence stream. Nested
# application roots are excluded while the root app remains auditable.
mkdir -p "$work/monorepo/app/models" \
  "$work/monorepo/service/app/controllers" \
  "$work/monorepo/service/config" \
  "$work/monorepo/engines/media/app/models"
printf 'GEM\n  specs:\n    activestorage (8.0.4)\n' > "$work/monorepo/Gemfile.lock"
printf 'GEM\n  specs:\n    activestorage (8.1.3)\n' > "$work/monorepo/service/Gemfile.lock"
printf 'module NestedService; class Application < Rails::Application; end; end\n' \
  > "$work/monorepo/service/config/application.rb"
printf 'class RootRecord < ApplicationRecord; has_one_attached :avatar; end\n' \
  > "$work/monorepo/app/models/root_record.rb"
printf 'params.require(:user).permit(:avatar) # nested_upload_only\n' \
  > "$work/monorepo/service/app/controllers/users_controller.rb"

# A nested lockfile is not sufficient to establish a separate runtime. Local
# engines and path dependencies remain in the host application's evidence.
printf 'GEM\n  specs:\n    media_engine (1.0.0)\n' \
  > "$work/monorepo/engines/media/Gemfile.lock"
printf 'class MediaAsset < ApplicationRecord; has_one_attached :engine_asset; end\n' \
  > "$work/monorepo/engines/media/app/models/media_asset.rb"
monorepo_out=$(sh "$subject" "$work/monorepo" 2>&1)
monorepo_status=$?
if [ "$monorepo_status" -ne 0 ]; then
  printf 'FAIL: excluding a nested application should keep the root audit usable\n'
  fail=1
fi
assert_contains 'Nested Rails application roots are excluded' "$monorepo_out"
assert_contains './service' "$monorepo_out"
assert_contains 'activestorage (8.0.4)' "$monorepo_out"
assert_not_contains 'activestorage (8.1.3)' "$monorepo_out"
assert_not_contains 'nested_upload_only' "$monorepo_out"
assert_contains 'Nested lockfile roots without config/application.rb remain in scope' "$monorepo_out"
assert_contains './engines/media' "$monorepo_out"
assert_contains 'has_one_attached :engine_asset' "$monorepo_out"

if sh "$subject" "$work/does-not-exist" >/dev/null 2>&1; then
  printf 'FAIL: nonexistent path should exit non-zero\n'
  fail=1
fi

[ "$fail" -eq 0 ] && printf 'OK: all assertions passed\n'
exit "$fail"
