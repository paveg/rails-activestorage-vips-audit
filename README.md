# rails-activestorage-vips-audit

An [Agent Skill](https://agentskills.io/specification) that audits Ruby on Rails repositories for exposure to **CVE-2026-66066** (_KindaRails2Shell_) — the Active Storage libvips variant-processing vulnerability that allows arbitrary file read and, in a Rails application, remote code execution.

The skill is a configuration auditor and remediation aid. It contains no exploit code and does not describe the attack chain.

## The vulnerability

|          |                                                                                               |
| :------- | :-------------------------------------------------------------------------------------------- |
| CVE      | CVE-2026-66066                                                                                |
| Severity | Critical, CVSS 9.5                                                                            |
| Package  | `activestorage` (RubyGems)                                                                    |
| Affected | `< 7.2.3.2`, `>= 8.0 < 8.0.5.1`, `>= 8.1 < 8.1.3.1`                                           |
| Patched  | `7.2.3.2`, `8.0.5.1`, `8.1.3.1`                                                               |
| Advisory | [GHSA-xr9x-r78c-5hrm](https://github.com/rails/rails/security/advisories/GHSA-xr9x-r78c-5hrm) |

libvips reads and writes formats through operations, some of which it marks as _unfuzzed_ — unsafe for untrusted content. Active Storage did not disable them, so an attacker who can upload a crafted file can reach them.

A repository is exposed only when **all four** conditions hold:

1. `activestorage` is in an affected version range
2. Active Storage is in use
3. `config.active_storage.variant_processor` resolves to `:vips`
4. The application accepts uploads from untrusted users

Condition 3 is the discriminating one. The affected range `< 7.2.3.2` includes every Rails 6.x release, but 6.x defaults to `:mini_magick`, so 6.x is exposed only under a non-default configuration, and releases before 6.0 have no `variant_processor` setting at all. Rails 7.0 and later default to `:vips` via `config.load_defaults 7.0`, which is why the common configuration is exposed.

## Installation

As a Claude Code plugin, through the marketplace bundled in this repository:

```
/plugin marketplace add paveg/rails-activestorage-vips-audit
/plugin install rails-activestorage-vips-audit@paveg-skills
```

With the [skills CLI](https://github.com/vercel-labs/skills), which installs the same skill into Claude Code, Codex, Cursor, Copilot CLI, and other agents:

```sh
npx skills add paveg/rails-activestorage-vips-audit
```

Or manually:

```sh
git clone https://github.com/paveg/rails-activestorage-vips-audit.git
cp -r rails-activestorage-vips-audit/skills/rails-activestorage-vips-audit ~/.claude/skills/
```

`~/.agents/skills/` works as a cross-runtime location for Codex, Copilot CLI, and Gemini CLI. Nothing in the skill depends on where it is installed — there are no absolute paths, and `collect-evidence.sh` resolves everything relative to the repository it is pointed at.

## Usage

The skill has two modes, and both accept multiple repository paths.

```
report <repo>...   # read-only audit, one verdict per repository
fix <repo>...      # applies remediation on a branch; never commits or pushes unprompted
```

Installed as a plugin, each mode is also a command, so the mode does not have to be typed as an argument:

```
/rails-activestorage-vips-audit:report path/to/app another/app
/rails-activestorage-vips-audit:fix path/to/app
```

The commands are entry points for you, not for the agent: they are marked so that Claude never fires them on its own. Claude still invokes the skill itself when a request matches it, which is why `fix` cannot start without a human asking for it.

`report` is the default. `fix` requires a `report` verdict for the same repository first, because the correct remediation depends on it — Rails 6.x, 7.0.x, and 7.1.x have no same-series patch, so there `fix` applies the interim mitigation and reports that a framework upgrade is required rather than attempting one.

Evidence collection can also be run on its own:

```sh
skills/rails-activestorage-vips-audit/scripts/collect-evidence.sh path/to/app another/app
```

The script gathers facts and deliberately contains no verdict logic.

## What it will not tell you

- **The runtime libvips version.** It is not knowable from a repository, and it matters: below libvips 8.13 the unsafe operations cannot be disabled at all. On an unpatched application that means no mitigation can work; on a patched one it means Active Storage raises during boot rather than running unsecured, so an unchecked upgrade fails the deploy instead of leaving a silent hole. Verify with `vips --version` where the application runs. Because of this, a clean verdict on an application that uses `:vips` is always reported as conditional rather than as safe.
- **Whether a mitigation is live.** `VIPS_BLOCK_UNTRUSTED` in a Dockerfile does not prove the deployed environment sets it. The skill caps such findings at "interim mitigation present, upgrade still required" and never lets one produce a clean verdict.

## Remediation summary

Upgrade to `7.2.3.2`, `8.0.5.1`, or `8.1.3.1`, matching your series. Confirm runtime libvips `>= 8.13` and `ruby-vips >= 2.2.1` **first**: where `ruby-vips` is installed, the patched Active Storage raises during boot unless both hold, and that check applies to `:mini_magick` applications too.

Interim mitigations, neither of which is a substitute for the upgrade:

- Set the `VIPS_BLOCK_UNTRUSTED` environment variable (libvips `>= 8.13`; no gem change needed)
- Call `Vips.block_untrusted(true)` from an initializer (`ruby-vips >= 2.2.1`, plus libvips `>= 8.13`)

On `ruby-vips < 2.2.1` the initializer route calls a method that does not exist yet, so raise the gem first or take the environment-variable route, which does not depend on it.

If an application was exposed, treat every secret readable by the application process as compromised and rotate it: `secret_key_base`, the master key, Active Storage service credentials, database credentials, and third-party tokens.

A WAF is not a mitigation here. Whether it can see the payload depends on the storage service and upload method, so its effectiveness is too configuration-dependent to rely on.

## Disclaimer

- Use this skill only on repositories you own or are explicitly authorized to audit.
- Verdicts are best-effort static analysis. A NOT AFFECTED verdict is not proof of non-exposure: evidence outside the repository (runtime libvips, deployed environment variables, code in other services) is invisible to a repository audit, which is why clean verdicts on `:vips` applications are always reported as conditional.
- The skill contains no exploit code and will not reconstruct the attack chain, regardless of how a request is framed.
- Provided under the [MIT License](LICENSE), without warranty of any kind. Acting on a report — upgrades, mitigations, secret rotation — remains the operator's responsibility.

## Sources

- [Rails security advisory GHSA-xr9x-r78c-5hrm](https://github.com/rails/rails/security/advisories/GHSA-xr9x-r78c-5hrm)
- [Ethiack — KindaRails2Shell: Rails RCE (CVE-2026-66066)](https://ethiack.com/info-hub/research/kindarails2shell-rails-rce-cve-2026-66066)
- [Rails guides — Configuring Rails Applications](https://guides.rubyonrails.org/configuring.html)

The vulnerability was found and reported independently by [RyotaK](https://x.com/ryotkak) of GMO Flatt Security and by a team from Ethiack consisting of André Baptista, Bruno Mendes, and Castilho, then disclosed in coordination with the Rails maintainers.
