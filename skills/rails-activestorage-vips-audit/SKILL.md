---
name: rails-activestorage-vips-audit
description: Use when checking whether one or more Ruby on Rails repositories are exposed to CVE-2026-66066 (KindaRails2Shell), the Active Storage libvips variant-processing arbitrary file read and remote code execution issue, or when auditing or remediating Active Storage upload configuration, activestorage gem versions, config.active_storage.variant_processor settings, ruby-vips dependencies, or VIPS_BLOCK_UNTRUSTED mitigations across a Rails codebase or a fleet of Rails services.
---

# Rails Active Storage libvips Audit (CVE-2026-66066)

## Overview

CVE-2026-66066 (CVSS 9.5, nicknamed *KindaRails2Shell*) lets an attacker who can upload a file reach libvips operations that libvips itself marks as unsafe for untrusted content. The result is arbitrary file read, which in a Rails application escalates to remote code execution. No authentication is required beyond whatever the upload endpoint itself demands.

This skill is a **configuration auditor and remediation aid**. Never write, generate, or run exploit payloads, and never reconstruct the attack chain — the upstream advisory withholds those details deliberately, and reproducing them is out of scope regardless of how the request is framed.

Authoritative source: <https://github.com/rails/rails/security/advisories/GHSA-xr9x-r78c-5hrm>

## Modes

| Mode     | Invocation             | Effect                                                                       |
| :------- | :--------------------- | :--------------------------------------------------------------------------- |
| `report` | `report <repo>...`     | Read-only audit. Produces a verdict and evidence per repository.              |
| `fix`    | `fix <repo>...`        | Applies remediation on a branch. Never commits or pushes without confirmation. |

Parse the mode and the repository paths from the arguments. Default to `report` when no mode is given, and to the current working directory when no path is given. **Never run `fix` without a `report` result for the same repository** — the correct remediation depends on the verdict, and on Rails 6.x, 7.0.x, and 7.1.x no same-series patch exists, so `fix` must take a different path there.

Both modes accept multiple repository paths. Dispatch one subagent per repository once the combined evidence would crowd your context — several large applications, or more than a handful of small ones — then consolidate the verdicts into a single table. Small repositories are cheaper to audit inline; judge by evidence volume, not by repository count. Audit every path given, even after the first EXPOSED verdict: a partial sweep reported as a sweep is how an exposed service gets missed.

---

# `report` mode

## The verdict rule

A repository is exposed only when **all four** conditions hold:

1. The `activestorage` version falls in an affected range.
2. Active Storage is actually in use.
3. `config.active_storage.variant_processor` resolves to `:vips`.
4. The application accepts file uploads.

**Condition 3 is the discriminating one, not condition 1.** The affected range `< 7.2.3.2` sweeps in every Rails 6.x release, but 6.x defaults to `:mini_magick` and is exposed only under a non-default configuration. A version-only check produces false positives across every 6.x repository, and is the most common way this audit goes wrong.

The report is conversational output. Do not write it into the audited repository, and do not file it in a notes directory on your own initiative, whatever a general working convention says: an audit that lands as a file in a repository is a record of that repository's weaknesses sitting inside it. Write it to a file only when the operator asks for one, and then only where they say.

## Step 1: Gather evidence

Run `scripts/collect-evidence.sh <repo>...`. It collects facts only and contains no verdict logic, so read its output and decide using the steps below.

## Step 2: Resolve the activestorage version

Read the `activestorage (X.Y.Z)` spec line from `Gemfile.lock`. The lockfile is authoritative; `Gemfile` constraints are not. In a monorepo, evaluate every `Gemfile.lock` independently.

| `activestorage` in `Gemfile.lock`                       | Status                |
| :------------------------------------------------------ | :-------------------- |
| `< 7.2.3.2` (every earlier release: 5.2.x, all 6.x, all 7.0.x, all 7.1.x, and `7.2.0` through `7.2.3.1`) | In the affected range |
| `7.2.3.2`                                               | Patched               |
| `>= 8.0` and `< 8.0.5.1` (including `8.0.4.1`, `8.0.5`) | In the affected range |
| `8.0.5.1`                                               | Patched               |
| `>= 8.1` and `< 8.1.3.1` (including `8.1.2.1`, `8.1.3`) | In the affected range |
| `8.1.3.1`                                               | Patched               |

Boundaries are one build segment apart, so compare them digit by digit rather than by eye: `7.2.3.1` is affected while `7.2.3.2` is patched, `8.0.5` is affected while `8.0.5.1` is patched, and `8.1.3` is affected while `8.1.3.1` is patched.

`variant_processor` does not exist before Rails 6.0 — Active Storage used ImageMagick unconditionally — so a release older than 6.0 cannot satisfy condition 3 whatever the version range says. Decide those on condition 3.

If `activestorage` is absent from the lockfile, the application does not load Active Storage. Report NOT AFFECTED and stop.

## Step 3: Confirm Active Storage is in use

Any one of these is sufficient evidence:

- `config/storage.yml` exists and `config.active_storage.service` is set.
- `active_storage_blobs` / `active_storage_attachments` appear in `db/schema.rb`, `db/structure.sql`, or `db/migrate/`.
- `has_one_attached` or `has_many_attached` appears in `app/models/`.
- `config/application.rb` loads the engine via `require "rails/all"` or `require "active_storage/engine"`.

**Do not require variant or transformation calls.** The advisory states variant generation is not a separate prerequisite, so gating on `variant(`, `processed`, or `image_processing` usage produces false negatives.

## Step 4: Resolve variant_processor

Rails applies configuration in load order — `config/application.rb`, then `config/environments/<env>.rb`, then `config/initializers/*.rb` — and the **last assignment wins**, because Active Storage reads the setting only after initialization finishes. Resolve accordingly and report the outcome **per environment**:

1. An **uncommented** `variant_processor` line in `config/initializers/`, most commonly `new_framework_defaults_*.rb`. Rails ships those commented out; a commented line does not apply. Initializers load last, so an uncommented line here overrides an explicit assignment in `application.rb` or an environment file — when both exist with different values, the initializer's value is the runtime value, and the report must flag the conflict rather than silently picking one.
2. An explicit `config.active_storage.variant_processor = :vips` or `= :mini_magick` in `config/environments/*.rb`. These are per-environment: an application setting `:mini_magick` in development while leaving production on `:vips` is production-exposed, and the report must name the environment.
3. An explicit assignment in `config/application.rb`. It runs first, so it yields to both of the above.
4. Otherwise `config.load_defaults X` in `config/application.rb` decides: `X >= 7.0` resolves to `:vips`, `X < 7.0` resolves to the built-in default `:mini_magick`.
5. If none of the above is present — no explicit setting, no uncommented framework-defaults line, and no `config.load_defaults` call at all — the built-in default applies and the processor is `:mini_magick`. Before concluding, check for an assignment in a mounted engine, a gem's railtie, or an environment variable read at boot, because an application with no `load_defaults` is usually a long-lived upgrade whose configuration lives somewhere unusual.

`ruby-vips` or `image_processing` in `Gemfile.lock` is supporting evidence that libvips is reachable, but does not by itself set the processor. A resolved value of `:mini_magick` means the application is not exposed through this path.

**`mini_magick` in `Gemfile.lock` does not mean the processor is `:mini_magick`.** Under `image_processing < 2.0.0` it arrives as a transitive dependency — that gemspec declares both `mini_magick` and `ruby-vips` — so finding it beside `ruby-vips` is the ordinary state of a `:vips` application, not a contradiction. From `image_processing 2.0.0` both became soft dependencies the application declares itself, which means their presence says even less about intent than before. Only the precedence above resolves the processor. The evidence script prints both gems, which is exactly why this misreading is available — it is the mirror image of declaring 6.x exposed on the version range alone, and just as easy to make.

A missing `config/environments/` directory, or one with no `variant_processor` line, means there is no per-environment override. That is a normal outcome, not a gap: report the single resolved value and name the rule that produced it.

## Step 5: Assess upload exposure

Check both routes into Active Storage, because they have different shapes:

- **Controller uploads** — strong parameters permitting an attachment attribute, or a form with `file_field`.
- **Direct uploads** — `direct_upload: true` on a `file_field`, the `rails_direct_uploads` route, or `DirectUpload` in JavaScript. These bypass controller strong parameters entirely, so an audit built only on permitted parameters will miss them.

Upload exposure is **confirmed** when the repository contains an entry point: a permitted parameter naming an attribute declared with `has_one_attached` or `has_many_attached`, a `file_field`, a direct-upload route, or a `permit!` call on parameters reaching a model that declares an attachment. It is **unconfirmed** when Active Storage is configured and in use but no entry point appears in this checkout — attachments may be created by another service, a background job, or code outside the repository. Unconfirmed maps to LIKELY EXPOSED. It never maps to NOT AFFECTED, because absent code is not absent behaviour.

Drive this from the attachment names, never from a keyword list. The evidence script derives the names from the `has_one_attached` and `has_many_attached` declarations and searches each one across the repository, so an attachment called `:resume` or `:logo` surfaces even though no fixed keyword list would contain it. The search matches both Ruby spellings of a parameter — the symbol form (`permit(:avatar)`) and the hash-label form (`permit(photos: [])`, the standard shape for `has_many_attached`) — so a Rails 8 `params.expect` list is matched as readily as a `permit` call. Where the script finds no declarations, it falls back to strong-parameter calls, capped and with the total printed; read those against Step 3.

**Read each match before counting it.** A generic attachment name matches text that has nothing to do with parameters — an attachment called `:file` also hits `render file:`, and `:image` hits view helpers. Confirm the line is a `permit`, `permit!`, or `params.expect` call, and that the attribute it names is the attachment, before treating it as an upload entry point. The cost of the derived-name search is this noise; the alternative, a fixed keyword list, silently misses `:resume` and `:logo` entirely, which is the worse failure.

`permit!` is reported separately because it names no attributes, so a search by attachment name cannot see it. Treat it as the strongest evidence available, not the weakest: it permits every attribute including the attachment. An application whose only controller evidence is `permit!` is confirmed exposed, even though its attachment name appears nowhere outside the model.

**A miss is still inconclusive, never evidence of absence.** Attachments can be created by a service object, a background job, or an API client whose code is not in this checkout. Since this criterion decides a verdict class, treating a miss as absence silently downgrades a genuinely exposed application by a full step.

The advisory frames the precondition as uploads from *untrusted* users, but source alone cannot establish who reaches an endpoint. So treat any upload path as untrusted for the verdict, and record authentication separately: it changes severity and urgency, not the verdict. **Detect authentication positively or not at all.** A missing `before_action :authenticate...` proves nothing: Devise's `authenticate_user!`, Pundit, route constraints, and rack middleware are all invisible to that grep, and a controller can inherit the filter from a parent class that is not in this repository. Report authentication as *not determined* unless you positively identify it, and never assert that an endpoint is unauthenticated from the absence of a match.

## Step 6: Check mitigations without downgrading the verdict

**A detected mitigation never yields a NOT AFFECTED verdict.** Static analysis cannot prove what the deployed runtime does.

| Evidence found                                                                             | What it proves                          | Maximum claim                                                                                             |
| :------------------------------------------------------------------------------------------ | :-------------------------------------- | :--------------------------------------------------------------------------------------------------------- |
| `Vips.block_untrusted(true)` in an initializer, with `ruby-vips >= 2.2.1` in `Gemfile.lock` | The application code requests the block | Interim mitigation present; upgrade still required                                                        |
| `VIPS_BLOCK_UNTRUSTED` in a Dockerfile, compose file, k8s manifest, or `Procfile`          | The variable is set somewhere in the repo | Unverified: inert unless runtime libvips is `>= 8.13`, and the deployed environment may differ from the repo |
| `VIPS_BLOCK_UNTRUSTED` in a `.env` file                                                    | Less than the row above                  | Weaker still: libvips reads the variable while initializing, which happens when `ruby-vips` is required, so a `.env` loaded by `dotenv-rails` can lose that race depending on Gemfile order |
| `ruby-vips` present but used only for analysis                                              | Nothing about variant processing        | No mitigation                                                                                             |
| A WAF rule                                                                                  | Nothing statically verifiable           | No mitigation                                                                                             |
| Upload content-type or MIME validation (`activestorage-validator`, a custom validator)      | Nothing about the file's contents       | No mitigation                                                                                             |
| No mitigation code at all, with `ruby-vips < 2.2.1`                                        | The initializer route is unavailable    | No mitigation, and the remediation must say which route remains — see below                              |

`Vips.block_untrusted(true)` with `ruby-vips < 2.2.1` calls a method that does not exist in that version. Flag it as a broken mitigation, not an effective one.

**When no mitigation is present and `ruby-vips < 2.2.1`, the mitigation is not broken, it is not yet reachable by that route.** This is the most common state, since an unremediated repository has no mitigation by definition. Do not recommend `Vips.block_untrusted(true)` as though it would work. Two routes remain, and they have different preconditions: `VIPS_BLOCK_UNTRUSTED` as an environment variable needs only runtime libvips `>= 8.13` and no gem change at all, while the initializer route needs `ruby-vips >= 2.2.1` first. The environment variable buys time on an application that cannot upgrade yet; it does not carry over to the upgrade, because the patched `activestorage` still requires `ruby-vips >= 2.2.1` to boot. Name the prerequisite as its own step rather than folding it into the mitigation, or the operator follows a procedure that cannot run.

Content-type validation earns a row for the same reason the WAF does, and it misleads harder: the file really is an image by every header the application checks. The unsafe operations are reached through the contents of a well-formed image, so a validator that only proves the declared type proves nothing about this.

## Step 7: Emit the report

One verdict per repository, from this set, followed by an evidence table naming the file and line that decided each of the four conditions:

- **EXPOSED** — all four conditions hold.
- **EXPOSED (interim mitigation present)** — all four conditions hold *and* the repository carries a well-formed mitigation: `Vips.block_untrusted(true)` with `ruby-vips >= 2.2.1`, or `VIPS_BLOCK_UNTRUSTED` in the deployment configuration. Use this label rather than inventing an annotation. It lowers the urgency, not the verdict, and the upgrade is still required.
- **LIKELY EXPOSED** — conditions 1 through 3 hold and upload exposure is unconfirmed by the Step 5 criterion.
- **NOT AFFECTED** — a condition is definitively false; name which one and the evidence. When the resolved processor is `:vips`, write it as conditional on runtime libvips, per the rule below.
- **INSUFFICIENT EVIDENCE** — a required file is missing or unreadable; name what you could not determine and what would settle it.

Cite the file and line that decided each condition. Where existence is itself the evidence — `config/storage.yml` being present, `config/environments/` being absent — cite the path alone and say that its existence is the finding.

**A verdict that reads clean must carry the runtime caveat when the resolved processor is `:vips`.** This applies to NOT AFFECTED and to LIKELY EXPOSED, and to those only. Write it into the verdict string — "NOT AFFECTED, conditional on runtime libvips `>= 8.13`" — and name `vips --version` as the check that settles it, rather than leaving the condition in prose while the verdict reads safe.

The reason is that the fix depends on libvips `>= 8.13` and `ruby-vips >= 2.2.1`, and no repository reveals either runtime fact. **The patched `activestorage` fails closed, not open.** When `ruby-vips` is installed and either minimum is unmet, it raises at boot rather than running unsecured — `Vips.respond_to?(:block_untrusted)` is false, and `active_storage/vips.rb` raises. So an application that upgrades without checking does not become quietly vulnerable; it stops booting. Report the caveat as what it is: the upgrade cannot be deployed until both minimums hold, and on an unpatched application an old libvips means no mitigation can work at all.

**Never attach the caveat to EXPOSED.** An old libvips does not make an exposed application conditionally exposed, it makes it worse. "EXPOSED, conditional on runtime libvips" reads as though a new enough libvips were the danger, which inverts the finding.

**Put that evidence in the remediation instead.** On an EXPOSED repository, evidence bearing on the runtime minimums — a base image whose distribution ships libvips below 8.13, or `ruby-vips` resolved below 2.2.1 in `Gemfile.lock` — belongs under remediation, where it tells the operator the upgrade will not boot until those are raised first. It is sequencing information, never a condition on the verdict. A prohibition with no destination gets broken, because the evidence is real and has to go somewhere.

No gem constraint can express the libvips version: `ruby-vips` is versioned `2.x` against a system library versioned `8.x`. `ruby-vips` in `Gemfile.lock` tells you about the 2.2.1 minimum and nothing about the 8.13 one.

**Name the line a clean verdict rests on.** When condition 1 holds and the verdict is NOT AFFECTED only because the processor resolved to `:mini_magick`, say that plainly: the application runs an affected `activestorage`, and a single configuration line is all that keeps the vulnerable path out of reach. Cite that line, and state that changing it — or adding a per-environment override, or a `load_defaults` bump during a Rails upgrade — flips the verdict with no dependency changing at all. A verdict that omits this reads as durable when it is one edit deep.

**Report what you saw outside the CVE's scope, outside the verdict.** Section 9 of the evidence collects code reaching libvips without going through Active Storage, such as `Vips::Image` or `ImageProcessing::Vips` in a job processing images the application fetched itself. That code does not satisfy condition 3 and must never move the verdict. Record it below the verdict as a separate observation, naming the file and what feeds it. A reader who sees NOT AFFECTED and no mention of libvips concludes that libvips is irrelevant to the application, which is a different claim and, where such a job exists, a false one.

If you happened to notice that variants are generated eagerly — an `after_create` hook or a job that processes every upload on arrival, rather than a variant built when someone views it — record it as a severity note, because the vulnerable path then runs on every upload with no viewer involved. **This is not an input to any of the four conditions, and its absence proves nothing.** Do not go looking for variant calls to decide exposure, and never let a repository with no such hook read as less likely to be exposed. Step 3 stands: variant generation is not a prerequisite.

State every condition you could not verify. An audit that hides its gaps is worse than one that reports them.

For multiple repositories, lead with a summary table of `repository | verdict | activestorage version | resolved processor`, then the per-repository detail. Order it by severity so the exposed ones are read first.

## Remediation summary

Include this in every report except an **unconditional** NOT AFFECTED — one where the resolved processor is `:mini_magick`, or `activestorage` is absent, so no runtime caveat applies. A NOT AFFECTED that carries the libvips caveat is not clean, and needs the summary.

Upgrade `activestorage` to `7.2.3.2`, `8.0.5.1`, or `8.1.3.1`, matching the application's series.

- The fix requires **libvips >= 8.13 and ruby-vips >= 2.2.1**, and both are preconditions of the upgrade itself, not only of the interim mitigation. Where `ruby-vips` is installed and either minimum is unmet, the patched `activestorage` raises at boot, so an upgrade shipped without checking produces a failed deploy. Order the work accordingly: raise `ruby-vips` and the base image first, then the framework gem. The `FROM` line in the Dockerfile determines which libvips ships, so name the base image as the thing to check, and say plainly that only `vips --version` in the running environment settles it.
- This boot check applies **whenever `ruby-vips` is installed**, including applications whose processor is `:mini_magick`. Such an application is not exposed through the variant path, but a patched `activestorage` will still refuse to boot on an old libvips. Say so when the verdict is NOT AFFECTED via `:mini_magick` and `ruby-vips` appears in the lockfile, or the operator meets it as a surprise during an unrelated upgrade.
- The patched `activestorage` calls `Vips.block_untrusted(true)`, which blocks the unsafe operations **process-wide**. Code calling `Vips::Image` directly is therefore covered by the upgrade too — which is why direct libvips use, collected in section 9 of the evidence, strengthens the case for upgrading even where the verdict is NOT AFFECTED.
- Rails 6.x, 7.0.x, and 7.1.x are end of life. For those, `7.2.3.2` is a **framework upgrade**, not a patch bump. Say this plainly and recommend the interim mitigation as something that buys time, not as a fix.
- If the application was exposed, treat **every secret readable by the application process as compromised** and rotate it: `secret_key_base`, the master key, Active Storage service credentials, database credentials, and third-party API tokens. This step is routinely forgotten and belongs in every EXPOSED report.

---

# `fix` mode

Read `references/fix-procedure.md` before making any change. It covers branch handling, the upgrade path per Rails series, the interim mitigation and when it is the only option, runtime libvips verification, and the secret rotation checklist.

Two rules that hold regardless of what the procedure says:

- **Never rotate secrets automatically.** Emit the checklist; the operator executes it. Rotating `secret_key_base` invalidates sessions and signed IDs, and rotating service credentials can break a running deployment.
- **Never commit or push without explicit confirmation.** Leave the working tree on a branch and report what changed.

---

## Common mistakes

| Mistake                                                            | Correction                                                             |
| :------------------------------------------------------------------ | :----------------------------------------------------------------------- |
| Declaring 6.x exposed on the version range alone                    | 6.x defaults to `:mini_magick`; require explicit `:vips` configuration  |
| Reading only `config/application.rb` for `variant_processor`        | `config/environments/*.rb` overrides it per environment                |
| Treating a commented `new_framework_defaults_7_0.rb` line as active | Commented lines do not apply; fall through to `load_defaults`          |
| Requiring `variant(` calls before flagging                          | Variant generation is not a prerequisite                               |
| Marking an app safe because `VIPS_BLOCK_UNTRUSTED` appears          | Unverifiable statically; cap at "interim mitigation present"            |
| Reading the version from `Gemfile` instead of `Gemfile.lock`        | Constraints are not resolved versions                                  |
| Upgrading `activestorage` while leaving libvips below 8.13 or `ruby-vips` below 2.2.1 | The patched gem raises at boot; the deploy fails rather than running unsecured |
| Saying a patched gem on an old libvips is "still exposed"           | It fails closed. The risk is a broken deploy and the sequencing that avoids it |
| Citing a gem constraint as evidence about the libvips version       | `ruby-vips` is `2.x` against a system library at `8.x`; no Gemfile line expresses it |
| Calling an endpoint unauthenticated because a `before_action` grep missed | Devise, Pundit, middleware, and inherited filters are invisible to it |
| Downgrading to NOT AFFECTED when no upload entry point is in the repo | Attachments may be created outside this checkout; that is LIKELY EXPOSED |
| Running `fix` without a `report` verdict                            | The remediation path depends on the verdict and the Rails series       |
| Omitting secret rotation from an EXPOSED report                     | Arbitrary file read means every readable secret is exposed             |
| Letting a clean verdict stand without naming the line it depends on | Condition 1 still holds; the verdict is one configuration edit deep    |
| Recommending `Vips.block_untrusted(true)` when `ruby-vips < 2.2.1`  | Not broken, not yet reachable; upgrade the gem first, or use the environment variable, which needs no gem change |
| Reading `mini_magick` in the lockfile as the resolved processor     | It arrives transitively with `image_processing`; only Step 4 resolves the processor |
| Counting content-type validation as a mitigation                    | The payload is a well-formed image; the declared type proves nothing   |
| Dropping libvips-below-8.13 evidence because it cannot touch an EXPOSED verdict | It belongs in the remediation, where it raises urgency     |
| Dropping direct `Vips::Image` calls because they are out of CVE scope | Report them as an observation; silence reads as "libvips is irrelevant here" |
| Writing or running a proof of concept                               | Out of scope; this skill audits and remediates configuration only      |
