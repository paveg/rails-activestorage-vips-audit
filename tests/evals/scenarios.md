# Empirical evaluation scenarios

These scenarios and checklists are fixed before execution. Do not relax them
after a failed run. `dynamic-processor` is the sealed hold-out and is used only
after two consecutive clean iterations on the loop scenarios.

## Scenario A — exposed application

Audit `fixtures/exposed` in report mode.

1. [critical] Verdict is `EXPOSED`.
2. The report cites evidence for all four exposure conditions.
3. Runtime readiness is separate from the verdict and identifies
   `ruby-vips 2.2.0` plus the unknown runtime libvips version.
4. Remediation sequences the runtime prerequisites before the Rails upgrade
   and includes secret rotation.
5. The verdict is not described as conditional on libvips.

## Scenario B — disabled processor and unrelated upload

Audit `fixtures/disabled-generic-upload` in report mode.

1. [critical] Verdict is `NOT AFFECTED` because the final processor is
   `:disabled`.
2. The CSV `file_field` is not counted as confirmed Active Storage use or an
   Active Storage upload.
3. The initializer is identified as overriding `config.load_defaults 8.1`.
4. Runtime readiness is reported separately because `ruby-vips` is bundled.

## Scenario C — monorepo application isolation

Audit both applications below `fixtures/monorepo` in report mode.

1. [critical] The applications are audited separately; evidence is never
   combined at the monorepo root.
2. `service-a` is `LIKELY EXPOSED`: version, Active Storage use, and `:vips`
   are confirmed while an upload entry point is not.
3. `service-b` is `NOT AFFECTED` because its processor resolves to
   `:mini_magick`, despite its confirmed attachment upload.
4. A summary table contains one row per application.
5. Runtime readiness is separate from both verdicts.

## Scenario D — application.rb source order

Audit both applications below `fixtures/processor-order` in report mode.

1. [critical] `explicit-before-defaults` is `EXPOSED`: the later
   `config.load_defaults 8.1` overwrites the earlier `:mini_magick`.
2. [critical] `explicit-after-defaults` is `NOT AFFECTED`: the later explicit
   `:mini_magick` assignment overwrites the defaults.
3. Both reports cite the assignment order rather than applying a fixed
   "explicit configuration wins" precedence.
4. Active Storage use and a correlated upload entry point are confirmed for
   both applications.

## Hold-out — dynamic processor

Audit `fixtures/dynamic-processor` in report mode.

1. [critical] Verdict is `INSUFFICIENT EVIDENCE` because the environment-derived
   processor cannot be resolved statically.
2. The evaluator does not fall through to `config.load_defaults 8.0`.
3. The affected version, confirmed attachment, and confirmed upload are still
   reported.
4. The report names the deployed `VARIANT_PROCESSOR` value as the evidence that
   would settle condition 3.
