# `fix` mode procedure — CVE-2026-66066

Remediation procedure for a repository that `report` mode has already judged. Read this in full before editing anything.

Unlike `report`, which only reads, `fix` executes code from the repository it is pointed at: `bundle update` evaluates the `Gemfile` as Ruby and may build native gem extensions. Run it only against a repository you own or are authorized to remediate. `report` is the mode that is safe to point at code you do not trust.

## Preconditions

Refuse to proceed and explain why when any of these hold:

| Condition                                 | Why `fix` must stop                                                                 |
| :---------------------------------------- | :---------------------------------------------------------------------------------- |
| No `report` verdict for this repository   | The correct path depends on the verdict and the Rails series. Run `report` first.   |
| Verdict is NOT AFFECTED                   | There is nothing to fix; changing dependencies adds risk for no benefit.            |
| Verdict is INSUFFICIENT EVIDENCE          | Resolve the unknowns first. Do not guess a remediation.                             |
| Working tree is dirty                     | Remediation changes must be reviewable in isolation.                                |

Create a branch per repository before the first edit, for example `security/cve-2026-66066`. Work only inside the repository you were given; never edit a sibling checkout because it looked related.

## Path A: the series has a patch release (7.2.x, 8.0.x, 8.1.x)

Target the matching patched version: `7.2.3.2` for 7.2.x, `8.0.5.1` for 8.0.x, `8.1.3.1` for 8.1.x.

1. If `Gemfile` pins the version (`gem "rails", "8.0.4"`), relax or raise the pin to the target. If it uses a pessimistic constraint that already admits the target, leave it alone.
2. Resolve through Bundler rather than hand-editing the lockfile:

   ```sh
   bundle update rails --conservative
   ```

   Use `bundle update activestorage --conservative` when the application depends on the framework gems individually rather than on `rails`. `--conservative` keeps unrelated dependencies still, which keeps the diff reviewable.
3. Confirm the result in `Gemfile.lock`: the `activestorage` spec line must now read the patched version. Do not claim the upgrade succeeded without showing that line.
4. Run the test suite and report the actual result, including failures.

**Never hand-edit `Gemfile.lock`.** A lockfile edited by hand can name a version whose dependency set was never resolved, which fails at deploy time rather than here.

## Path B: the series is end of life (6.x, 7.0.x, 7.1.x)

No patch exists for these series. `7.2.3.2` is a framework upgrade spanning several major versions, with its own deprecations and behavioural changes. **Do not attempt that upgrade as part of `fix`.** Instead:

1. Apply the interim mitigation below, if its preconditions hold.
2. Report clearly that the framework upgrade is required, is the only real fix, and is out of scope for automated remediation. Estimate nothing you have not investigated.
3. If the interim mitigation cannot be applied either — for instance `ruby-vips < 2.2.1` and runtime libvips below 8.13 — say that the application has no available mitigation short of disabling untrusted uploads or switching `variant_processor` to `:mini_magick`, and let the operator choose.

## The interim mitigation

Preconditions: `ruby-vips >= 2.2.1` in `Gemfile.lock` **and** runtime libvips `>= 8.13`. Below either, the mitigation is inert — applying it anyway creates a false sense of safety, which is worse than no mitigation.

```ruby
# config/initializers/vips_block_untrusted.rb
# Interim mitigation for CVE-2026-66066. Blocks libvips operations that libvips
# marks as unsafe for untrusted content. Requires ruby-vips >= 2.2.1 and
# libvips >= 8.13; it cannot take effect below either version.
require "vips"

if Vips.respond_to?(:block_untrusted)
  Vips.block_untrusted(true)
else
  raise "ruby-vips is too old to block untrusted operations (CVE-2026-66066); upgrade ruby-vips to >= 2.2.1 or upgrade Rails"
end
```

Raising at boot is deliberate. A mitigation that silently does nothing is the failure mode this whole audit exists to prevent, and a boot failure in staging is far cheaper than an undetected exposure in production. If the operator prefers a warning over a hard failure, that is their call to make explicitly — do not soften it on your own initiative.

`VIPS_BLOCK_UNTRUSTED` as an environment variable is equivalent and may suit a deployment that cannot ship code changes quickly. Setting it in the repository does not set it in the deployed environment; if you add it to a Dockerfile or manifest, say in the report that the deployment must be verified.

## Runtime libvips verification

This cannot be resolved from the repository, and it is not optional: **below libvips 8.13 the unsafe operations cannot be disabled at all**, so the `activestorage` upgrade alone does not close the hole.

Ask the operator to run this where the application actually runs:

```sh
vips --version
```

If the deployment builds from a Dockerfile, check the base image. Rails' generated Dockerfiles and Debian/Ubuntu images install libvips by default, which is exactly why the default configuration is exposed; the version that arrives depends on the distribution release. When the base image ships libvips below 8.13, the remediation is incomplete until the base image is updated, and the report must say so.

## Secret rotation

If the verdict was EXPOSED, emit this checklist. **Do not rotate anything automatically** — rotating `secret_key_base` invalidates sessions and signed IDs, and rotating service credentials can break a running deployment.

- [ ] `secret_key_base`
- [ ] `config/master.key` and any `config/credentials/*.key`
- [ ] Active Storage service credentials (S3, GCS, Azure)
- [ ] Database credentials
- [ ] Third-party API tokens and webhook signing secrets readable by the app process
- [ ] Any private keys mounted into the application container

Rotation is warranted whenever the application was exposed, because arbitrary file read means every secret the application process could read may already have been taken. Absence of evidence in the logs is not evidence the read did not happen.

## Finishing

Report what changed, what was verified with which command and its output, and what remains for the operator. Leave the branch in place. **Do not commit or push without explicit confirmation**, and never open a pull request on your own initiative — a security-fix branch pushed to a public remote before the operator is ready discloses the exposure.
