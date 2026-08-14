# Phase 2, Stage 2b — resource-identity and contract-breaking changes (design only)

**Status: NOT STARTED. NOT APPROVED FOR IMPLEMENTATION.**

This document is a design record for future work, not an implementation. No file listed below has
been renamed, moved, or had its physical or logical CloudFormation identity changed as part of writing
this document. Per `rebrand-plan.md` section 22.1, Stage 2b requires a separate, explicit approval that
is not implied by approval of Phase 1, of this plan, or of Phase 2 Stage 2a. That approval has not been
given. This document exists so the design is ready when it is.

## Why this is a separate stage, not a separate document that gets forgotten

Stage 2a (additive aliases, implemented — see `deployment/2-aiml-security-codebuild.yaml`,
`deployment/aiml-security-single-account.yaml`, `buildspec.yml`, `tests/test_alias_precedence.py`) and
Stage 2b share one phase number in `rebrand-plan.md` v3, but they do not share a review boundary, a
risk profile, or an approval gate. Stage 2a is reversible: every artifact it added is additive, and
removing `EnableResponsibleAIGovAssessment` / `ENABLE_RESPONSIBLE_AI_GOV` tomorrow would not break any
customer relying only on the legacy `EnableFinServAssessment` name. Everything in this document is the
opposite: renaming a CloudFormation logical ID or physical Lambda name is a replacement operation, and
renaming a Step Functions state name changes what appears in a customer's execution history forever.

## Preconditions from the plan (not yet met)

Per `rebrand-plan.md` section 21.2:

1. Stage 2a has shipped and run in production for at least one deployment cycle with no reported alias
   conflicts. **Not met** — Stage 2a has not yet been reviewed or merged.
2. Explicit, separate sign-off to proceed. **Not obtained.**
3. A deprecation period, migration guide, archived-report converter, stack replacement plan, and
   rollback rehearsal drafted and reviewed. **Partially drafted** — see the companion migration guide
   (`docs/RESPONSIBLE_AI_GRC_ALIAS_MIGRATION.md`) and converter utility
   (`scripts/convert_finserv_csv_prefix.py`), both scoped to Stage 2a's own rollout, not to Stage 2b.
   Stage 2b needs its own versions of these, covering the changes below.

## Scope: what Stage 2b would change

This is the unrenumbered content of v2's "Phase 3 — major release only" (`rebrand-plan.md` section
18.3, Stage 2b), organized here by resource so a future implementer can see the blast radius of each
change independently.

### 1. Physical Lambda function name

**Current:** `aiml-security-${AWS::StackName}-FinServAssessment` (`template.yaml`,
`template-multi-account.yaml`, `AWS::Lambda::Function.FunctionName`).

**Constraint (already recorded in `rebrand-plan.md` section 14 and enforced by
`tests/test_legacy_contracts.py::test_function_name_fits_the_lambda_limit`):** the worst-case fixed
portion of the rendered name is 41 characters against Lambda's 64-character limit, leaving a
**23-character suffix budget**. `ResponsibleAIGRCAssessment` (26 chars) and
`ResponsibleAIGovAssessment` (26 chars) are both infeasible. The recorded feasible candidate is
**`RAIGRCAssessment`** (16 chars).

**Why this is a replacement, not an update:** `AWS::Lambda::Function.FunctionName` is not a
mutable property in the sense CloudFormation can update in place when driven by a template change to a
`!Sub` expression that resolves differently — changing the rendered name forces CloudFormation to
create a new function and delete the old one. That changes the function's ARN, which appears in:

- The IAM policies granting it permissions (would need to be re-derived or the change coordinated
  with the CR).
- CloudWatch Logs group name (`/aws/lambda/<function-name>`), meaning historical logs become
  unreachable from the new function's log group.
- Any customer automation that referenced the ARN directly (unlikely given this is a Step
  Functions-orchestrated internal component, but not something this document can rule out for every
  deployment).
- The `FS-67` self-exclusion logic in `finserv_assessments/app.py`, which derives its own sibling-Lambda
  prefix from `AWS_LAMBDA_FUNCTION_NAME` at runtime (see Phase 1 commit history) — a rename does not
  break this mechanism since it is derived, not hardcoded, but it must be re-verified against the new
  name before this ships.

**Design for implementation (when approved):** rename to `RAIGRCAssessment` in a single coordinated
change across both SAM templates, verified with a CloudFormation change set against a disposable stack
first (per `rebrand-plan.md` section 9.3's change-set gate), confirming the change set shows exactly one
expected `Replacement: True` for this resource and no unexpected replacements elsewhere.

### 2. CloudFormation logical ID

**Current:** `FinServSecurityAssessmentFunction`.

Renaming a logical ID is, on its own, **always** a replacement in CloudFormation regardless of whether
the physical name changes — CloudFormation tracks resources by logical ID within a template, so a new
logical ID is a new resource to CloudFormation even if `FunctionName` is held constant. This means
items 1 and 2 are two independent replacement triggers, not one; a design that changes only the
physical name and not the logical ID (or vice versa) still causes replacement.

**Design for implementation:** if both are changing together, this is one net replacement rather than
two, but the change-set gate must confirm that explicitly rather than assume it.

### 3. Step Functions state names and result path

**Current:** `"FinServ Enabled?"`, `"FinServ Security Assessment"`, `"FinServ Assessment Incomplete"`,
`"FinServ Assessment Skipped"`, and `"ResultPath": "$.finservError"`
(`aiml-security-assessment/statemachine/assessments.asl.json`).

**Why this is different from 1 and 2:** state names are not CloudFormation-replacement risks — the
state machine resource itself does not need to be replaced to rename a state within it. The actual
risk is **customer-visible history discontinuity**: every execution run before the rename shows the
old state names in the Step Functions console and in `DescribeExecution`/`GetExecutionHistory` API
responses; every execution after the rename shows the new ones. There is no way to retroactively
relabel historical executions, so any customer runbook, alarm, or dashboard that pattern-matches on a
specific state name (for example, an EventBridge rule filtering on
`detail.stateEnteredEventDetails.name == "FinServ Security Assessment"`) breaks silently at the moment
of deployment, with no error — the state machine keeps working, but the customer's *monitoring* of it
stops matching.

**Design for implementation:** rename to something like `"Responsible AI GRC Enabled?"`,
`"Responsible AI GRC Security Assessment"`, `"Responsible AI GRC Assessment Incomplete"`,
`"Responsible AI GRC Assessment Skipped"`, and `"$.responsibleAIGRCError"`. Verify each new name against
the Step Functions state-name length limit (80 characters — `rebrand-plan.md` section 14 already
computed the longest candidate, `Responsible AI GRC Assessment Incomplete`, at 40 characters, well
within budget). Publish the rename in a changelog with an explicit callout for anyone monitoring state
names, at least one deprecation-period release ahead of the change landing.

### 4. Report DOM selectors and CSS classes

**Current, frozen by `tests/test_legacy_contracts.py`:** `id="finserv"`, `data-service="finserv"`,
`data-filter-service="finserv"`, `data-scope-service="finserv"`, `<option value="finserv">`,
`href="#finserv"`, and the CSS classes `industry-item`, `industry-nav`, `industry-chip`,
`scope-industry`, `scope-industry-label`.

**Why this is different again:** unlike 1–3, this is not a runtime-identity or monitoring risk, it is
an **archived-artifact rendering risk**. Every HTML report ever generated under the old selectors is a
static file already sitting in a customer's S3 bucket or downloaded locally. If the *live* code
changes selectors, a customer's browser bookmark to a specific anchor (`#finserv`) in an already
downloaded report keeps working (the archived HTML is immutable), but any tooling that scrapes
*newly generated* reports for the old `data-service="finserv"` attribute stops matching from the day of
the change forward, with the same silent-breakage character as item 3.

**Design for implementation:** if approved, do not do a blanket rename. Introduce the new selector
alongside the old one for at least one deprecation-period release (`data-service="finserv"
data-service-alias="responsible-ai-grc"`, or a second, additive `id`/anchor), remove the legacy selector
only in a release explicitly flagged as breaking, and update
`tests/test_legacy_contracts.py::test_report_selectors_are_frozen` and
`::test_report_css_classes_are_frozen` to encode the new frozen set rather than deleting the old
assertions outright — the test file's own docstring is explicit that "if a rename makes one of these
fail, the rename is wrong, not the test," and that principle should still hold for whatever selector set
is frozen next.

### 5. CSV filename prefix

**Current, frozen by `tests/test_legacy_contracts.py::test_csv_prefix_is_frozen`:**
`finserv_security_report_{execution_id}.csv`.

**Design for implementation:** per `rebrand-plan.md` section 18.3 Stage 2a, if a new prefix
(`responsible_ai_gov_security_report_{execution_id}.csv`) is ever approved, both objects must be written
atomically, both read on ingestion, deduplicated by execution ID + account + region + service + check ID
+ finding identity, the legacy object preserved indefinitely, and both prefixes excluded from the report
bucket sync when the capability ran only as an OWASP dependency (mirroring the existing
`fs_exclude_args` logic in `buildspec.yml`, which would need a second `--exclude` entry).

A companion converter utility for reading either prefix already exists at
`scripts/convert_finserv_csv_prefix.py` (see the migration guide), written ahead of need so it is ready
the day a new prefix is approved — it does not currently run against any real prefix change because
none has been approved.

### 6. Documentation filenames

**Current:** `docs/SECURITY_CHECKS_FINSERV.md`, `docs/SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md`,
`docs/SECURITY_CHECKS_FINSERV_SEVERITY_REGISTER.md`.

**Why this is the highest-friction item on this list:** these three files are published on GitHub
Pages and are search-indexed. Unlike items 1–5, which are internal-identity or monitoring risks, this
is a **public-URL risk**: an external search result or a bookmark pointing at
`https://aws-samples.github.io/sample-aiml-security-assessment/docs/SECURITY_CHECKS_FINSERV.html`
returns a 404 the moment the file is renamed or removed, with no way to intercept the request (GitHub
Pages serves static files; there is no server-side redirect layer to configure).

**Design for implementation:** if renamed, the old filename must be preserved as a redirect stub — a
minimal HTML file at the old path containing `<meta http-equiv="refresh" content="0; url=NEW_PATH">` and
a visible "this page has moved" message with a manual link, committed in the *same* change that
introduces the new filename, never as a follow-up. `rebrand-plan.md` section 22.2's no-go criteria
already treat "any published GitHub Pages URL is broken without a redirect stub" as a release blocker,
and that criterion applies to Stage 2b exactly as it did to the "Phase 3" it was originally written
for.

### 7. `FS-*` check ID renumbering

**Explicitly rejected**, not merely deferred. `rebrand-plan.md` section 23.1 records "`FS-*`
renumbering: Rejected. Preserve all IDs including `FS-00`" as a resolved decision, not a pending one.
This item is listed here only for completeness of the Stage 2b scope inherited from v2's "Phase 3", and
restating the rejection: renumbering breaks historical CSV comparison, the 42 OWASP `FS-*` mapping keys,
every test asserting a specific ID, the severity register, and any future Security Hub ASFF export
(where `FS-*` values become `GeneratorId` values per issue #36). Nothing in Stage 2b's design should
revisit this.

### 8. Redundant `aiml-security-` prefix removal

**Current:** the rendered member-account physical name is
`aiml-security-aiml-security-<acct>-FinServAssessment` — the literal `aiml-security-` prefix appears
twice, once from the stack name and once from the `!Sub` expression, wasting 14 of the 64 available
characters. Dropping the redundant prefix from the `!Sub` expression is itself a physical rename
(triggers the same replacement risk as item 1) and must be bundled with item 1 if both are done, not
scheduled as a separate follow-up that leaves the resource in an intermediate renamed-once state.

## What this document deliberately does not do

- It does not change `template.yaml`, `template-multi-account.yaml`,
  `aiml-security-assessment/statemachine/assessments.asl.json`, `report_template.py`,
  `consolidate_html_reports.py`, or any of the three `docs/SECURITY_CHECKS_FINSERV*.md` files.
- It does not create redirect stubs, because no file has moved yet.
- It does not touch `tests/test_legacy_contracts.py`'s frozen assertions, because nothing they assert
  has changed.
- It does not open a CR, a GitHub issue, or a PR for any of the above.

## Next steps (require explicit approval before proceeding)

1. Confirm Stage 2a has been running in production for at least one full deployment cycle with no
   reported `EnableFinServAssessment` / `EnableResponsibleAIGovAssessment` conflicts.
2. Obtain and record explicit sign-off to begin Stage 2b, naming which of the eight items above are in
   scope for the first Stage 2b release (they do not all need to land together — items 4–6 in
   particular can be sequenced independently of items 1–3).
3. Draft the deprecation-period customer communication and the rollback rehearsal plan required by
   `rebrand-plan.md` section 21.2's Stage 2b sequence, specific to whichever items are chosen in step 2.
4. Only then begin editing the resource-identity-bearing files listed above, each behind its own
   change-set-gated CR.
