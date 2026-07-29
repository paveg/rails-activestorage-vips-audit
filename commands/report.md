---
description: Audit Rails repositories for CVE-2026-66066 (Active Storage / libvips) exposure. Read-only.
argument-hint: "[repo-path...]"
disable-model-invocation: true
---

Run the `rails-activestorage-vips-audit` skill in `report` mode against: $ARGUMENTS

Default to the current working directory when no path is given. Audit every path given, even after the first EXPOSED verdict.

This mode is read-only. Make no edits, and never write or run a proof of concept.
