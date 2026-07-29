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
  "$app/sub/node_modules/dep" "$app/engines/x/vendor/bundle/gems/dep"

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

# The hash-label strong parameter is how has_many_attached attributes are
# permitted; the :photos search must find it, not only the symbol form.
assert_contains 'permit(:name, photos: [])' "$out"

# Derived names are clean symbol literals only; unparseable declarations are
# surfaced for manual resolution instead of leaking through as regex garbage.
assert_contains 'Declared attachment names: photos' "$out"
assert_contains 'no symbol-literal name' "$out"
assert_not_contains 'no reference to :{' "$out"

# Vendored third-party code stays out of the evidence at any depth.
assert_not_contains 'from_vendored_code' "$out"

# Non-ERB templates and JSX/TSX bundles are inside the search surface.
assert_contains 'uploader.tsx' "$out"
assert_contains 'form.html.haml' "$out"

# A repository without a lockfile reports that, never a silent empty section.
assert_contains 'none found: Gemfile.lock' "$out"

# libvips reached outside Active Storage is out of scope for the verdict, but
# dropping it from the evidence lets a reader conclude libvips is irrelevant.
assert_contains 'Vips::Image.new_from_file' "$out"
assert_contains 'ImageProcessing::Vips.source' "$out"

# The no-declarations fallback stays readable: capped, with the total stated.
assert_contains 'field_01' "$out"
assert_contains 'showing 15 of 30' "$out"
assert_not_contains 'field_30' "$out"

if sh "$subject" "$work/does-not-exist" >/dev/null 2>&1; then
  printf 'FAIL: nonexistent path should exit non-zero\n'
  fail=1
fi

[ "$fail" -eq 0 ] && printf 'OK: all assertions passed\n'
exit "$fail"
