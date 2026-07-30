---
description: Apply CVE-2026-66066 remediation on a branch, after a report verdict for the same application.
argument-hint: "[app-path...]"
disable-model-invocation: true
---

Run the `rails-activestorage-vips-audit` skill in `fix` mode against: $ARGUMENTS

Read `references/fix-procedure.md` in full before changing anything. Refuse to proceed when there is no `report` verdict for the application, when the verdict was NOT AFFECTED or INSUFFICIENT EVIDENCE, or when the working tree is dirty.

This mode executes code from the repository it is pointed at: `bundle update` evaluates the `Gemfile` as Ruby. Never rotate secrets automatically, and never commit or push without explicit confirmation.
