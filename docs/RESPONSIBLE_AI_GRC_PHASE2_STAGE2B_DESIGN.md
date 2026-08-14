# Phase 2, Stage 2b — resource-identity and contract-breaking changes

**Status: IMPLEMENTED IN THIS WORKSPACE. NOT APPROVED FOR MERGE OR DEPLOYMENT.**

This document originally recorded a design with zero implementation. That is no longer accurate: items
1, 2, 3, 4, and 5 below are now implemented, committed to the local
`feat/rebrand-phase2-stage2b-breaking-changes` branch, and fully tested. Items 6 and 7 are explicitly
**not implemented and not scheduled** — see their sections for why. Item 8 is explicitly **not
implemented**, superseding the original design: implementing it as originally scoped would have broken
a runtime mechanism this document did not originally account for (see item 8 below).

**What "implemented" does and does not mean here:** every change below exists only in this local
workspace, on a branch that has not been reviewed, has not had a CR opened, and has not been deployed
anywhere. The preconditions in `rebrand-plan.md` section 21.2 — Stage 2a running in production for a
full deployment cycle, and a separate explicit sign-off to begin Stage 2b — are **still not met**. This
document being marked "implemented" reflects that the code exists and passes tests locally, not that
Stage 2b has been approved to ship. That approval gate has not moved.

## Why this is a separate stage, not a separate document that gets forgotten

Stage 2a (additive aliases — see `deployment/2-aiml-security-codebuild.yaml`,
`deployment/aiml-security-single-account.yaml`, `buildspec.yml`, `tests/test_alias_precedence.py`) and
Stage 2b share one phase number in `rebrand-plan.md` v3, but they do not share a review boundary, a
risk profile, or an approval gate. Stage 2a is reversible: every artifact it added is additive, and
removing `EnableResponsibleAIGovAssessment` / `ENABLE_RESPONSIBLE_AI_GOV` tomorrow would not break any
customer relying only on the legacy `EnableFinServAssessment` name. Items 1–3 below are the opposite:
renaming a CloudFormation logical ID or physical Lambda name is a replacement operation, and renaming a
Step Functions state name changes what appears in a customer's execution history forever. Items 4–5 were
implemented additively specifically to avoid that same irreversibility.

## Preconditions from the plan (still not met)

Per `rebrand-plan.md` section 21.2:

1. Stage 2a has shipped and run in production for at least one deployment cycle with no reported alias
   conflicts. **Not met** — Stage 2a has not yet been reviewed or merged, let alone deployed.
2. Explicit, separate sign-off to proceed. **Not obtained.** Implementing the code in this workspace is
   not that sign-off; it is preparatory work done so the sign-off decision has a concrete diff to react
   to.
3. A deprecation period, migration guide, archived-report converter, stack replacement plan, and
   rollback rehearsal drafted and reviewed. **Partially drafted** — `docs/RESPONSIBLE_AI_GRC_ALIAS_MIGRATION.md`
   and `scripts/convert_finserv_csv_prefix.py` cover Stage 2a's rollout. Items 4 and 5 below are
   additive, so they do not themselves need a deprecation period or rollback rehearsal — nothing they
   add can be un-added without customer impact. Items 1–3, if ever promoted from "implemented locally"
   to "approved to ship," still need their own deprecation-period customer communication (see item 3's
   design section) before that promotion.

## Implementation summary

| Item | Status | What changed |
|---|---|---|
| 1. Physical Lambda name | **Implemented (suffix only)** | `...-FinServAssessment` → `...-RAIGRCAssessment`. The `aiml-security-` prefix is unchanged — see item 8. |
| 2. CloudFormation logical ID | **Implemented** | `FinServSecurityAssessmentFunction` → `ResponsibleAIGRCAssessmentFunction` |
| 3. ASL state names, result path, substitution key | **Implemented** | All four state names, `$.finservError` → `$.responsibleAIGRCError`, `${FinServSecurityAssessmentFunction}` → `${ResponsibleAIGRCAssessmentFunction}` |
| 4. Report DOM selectors | **Implemented, additive only** | New `responsible-ai-grc`-named attributes/anchor added alongside every legacy selector. Zero legacy selectors removed or altered. |
| 5. CSV filename prefix | **Implemented, additive only** | `responsible_ai_gov_security_report_{execution_id}.csv` now dual-written, dual-read, and deduplicated alongside the legacy prefix. |
| 6. Documentation filenames | **Not implemented — deferred indefinitely** | See its section. |
| 7. `FS-*` renumbering | **Not implemented — rejected** | See its section. |
| 8. Redundant `aiml-security-` prefix removal | **Not implemented — rejected for a reason this document did not originally anticipate** | See its section. |

## Scope: what Stage 2b changes

This is the unrenumbered content of v2's "Phase 3 — major release only" (`rebrand-plan.md` section
18.3, Stage 2b), organized here by resource so a reviewer can see the blast radius of each change
independently.

### 1. Physical Lambda function name — implemented, suffix only

**Before:** `aiml-security-${AWS::StackName}-FinServAssessment` (`template.yaml`,
`template-multi-account.yaml`, `AWS::Lambda::Function.FunctionName`).
**After:** `aiml-security-${AWS::StackName}-RAIGRCAssessment`.

**Constraint (recorded in `rebrand-plan.md` section 14, enforced by
`tests/test_legacy_contracts.py::test_function_name_fits_the_lambda_limit`, now parametrized across all
three real stack-name forms — single-account, multi-account member, and management):** the worst-case
fixed portion of the rendered name is 41 characters against Lambda's 64-character limit, leaving a
**23-character suffix budget**. `ResponsibleAIGRCAssessment` (26 chars) and `ResponsibleAIGovAssessment`
(26 chars) are both infeasible — asserted directly by
`test_infeasible_full_name_candidates_are_recorded_as_infeasible`. The suffix actually used,
**`RAIGRCAssessment`** (16 chars), is also shorter than the retired 17-character `FinServAssessment`
it replaces.

**Why this is a replacement, not an update:** `AWS::Lambda::Function.FunctionName` cannot be updated in
place when a `!Sub` expression resolves to a different value — CloudFormation creates a new function and
deletes the old one. That changes the function's ARN, which appears in the IAM policies granting it
permissions, the CloudWatch Logs group name (`/aws/lambda/<function-name>`, making historical logs
unreachable from the new function's log group), and any customer automation that referenced the ARN
directly.

**Why the prefix is unchanged (this is the load-bearing decision of this item):**
`finserv_assessments/app.py`'s `_self_lambda_name_prefix()` derives the FS-67 self-exclusion prefix by
checking `AWS_LAMBDA_FUNCTION_NAME.startswith("aiml-security-")` — a literal string check, not one
derived from the stack name. Dropping that prefix (as item 8 originally proposed) would have silently
disabled self-exclusion for **every** sibling assessment Lambda, not just this one — see item 8. Only
the suffix segment was changed for that reason.
`tests/test_legacy_contracts.py::test_own_lambda_prefix_matches_self_exclusion_assumption` locks this in.

**Verification performed:** `cfn-lint` clean on both templates; `sam validate --lint` passes both;
`sam build` succeeds for both templates, with the built template confirmed (by direct inspection of
`.aws-sam/build/template.yaml`) to resolve `Fn::GetAtt`, `Ref`, and the `FunctionName` `Fn::Sub`
expression correctly against the new logical ID and suffix.

### 2. CloudFormation logical ID — implemented

**Before:** `FinServSecurityAssessmentFunction`. **After:** `ResponsibleAIGRCAssessmentFunction`.

Renamed together with item 1 across `template.yaml` and `template-multi-account.yaml`: the
`DefinitionSubstitutions` entry, every `LambdaInvokePolicy.FunctionName` reference, and the resource
block itself. Renaming a logical ID is, on its own, always a CloudFormation replacement regardless of
whether the physical name changes, so items 1 and 2 landing together is one net replacement, not two —
confirmed by the successful `sam build` resolving both consistently, not merely asserted.

### 3. Step Functions state names and result path — implemented

| Retired | Replacement |
|---|---|
| `"FinServ Enabled?"` | `"Responsible AI GRC Enabled?"` |
| `"FinServ Security Assessment"` | `"Responsible AI GRC Security Assessment"` |
| `"FinServ Assessment Incomplete"` | `"Responsible AI GRC Assessment Incomplete"` |
| `"FinServ Assessment Skipped"` | `"Responsible AI GRC Assessment Skipped"` |
| `"ResultPath": "$.finservError"` | `"ResultPath": "$.responsibleAIGRCError"` |
| `"${FinServSecurityAssessmentFunction}"` | `"${ResponsibleAIGRCAssessmentFunction}"` |

**Why this is different from items 1–2:** state names are not a CloudFormation-replacement risk — the
state machine resource itself is not replaced to rename a state within it. The risk is
**customer-visible history discontinuity**: executions before this change show the old state names in
the Step Functions console and `DescribeExecution`/`GetExecutionHistory` responses; executions after
show the new ones, with no way to retroactively relabel history. Any customer runbook, alarm, or
EventBridge rule pattern-matching on a specific state name breaks silently at deployment time — the
state machine keeps working, but the customer's monitoring of it stops matching.

**Verification performed:** `aiml-security-assessment/statemachine/assessments.asl.json` re-verified
structurally valid (parses as JSON once the one genuine unquoted numeric substitution,
`${MaxRegionConcurrency}`, is normalized — the file is not standalone-valid JSON by design, per its own
comment and `test_asl_is_a_substituted_template_not_plain_json`). All four new state names confirmed
present and all four retired names confirmed **absent** —
`tests/test_legacy_contracts.py::test_retired_finserv_asl_state_names_are_gone` and its siblings assert
absence explicitly, not just presence of the new names, specifically to catch a partial rename that
would leave a dangling `Next`/`Default` reference. New state name lengths all well under the Step
Functions 80-character limit (longest is 41 characters).

**Not done as part of this item:** no customer-facing changelog entry or deprecation-period notice has
been published, because nothing has shipped. That publication step belongs to whatever release process
eventually promotes this branch, not to this implementation.

### 4. Report DOM selectors and CSS classes — implemented, additive only

**Unchanged, still frozen by `tests/test_legacy_contracts.py`:** `id="finserv"`,
`data-service="finserv"`, `data-filter-service="finserv"`, `data-scope-service="finserv"`,
`<option value="finserv">`, `href="#finserv"`, and the CSS classes `industry-item`, `industry-nav`,
`industry-chip`, `scope-industry`, `scope-industry-label`. None of these were renamed, removed, or had
their values altered.

**Added, in `report_template.py`:**

- A module constant `RESPONSIBLE_AI_GRC_SLUG_ALIAS = "responsible-ai-grc"`.
- `data-service-alias="responsible-ai-grc"` on the FinServ scope block, alongside the existing
  `data-scope-service="finserv"`.
- `data-service-section-alias="responsible-ai-grc"` on the FinServ `<section>`, plus a hidden
  `<span id="responsible-ai-grc" aria-hidden="true">` anchor immediately before it.
- A per-row `data-service-alias="responsible-ai-grc"` attribute in `generate_table_rows()`, added only
  when a row's `_service == "finserv"`.

**Deliberately not added:** a second `<option>` dropdown entry, or a second `data-filter-service` button
value. The in-report client-side filter (`applyFilters()`) matches `data-service` by exact string
against the single `<option value="finserv">` entry; introducing a second dropdown option pointing at a
`data-service` value that no row actually carries would produce a filter control that looks functional
but silently returns zero rows. Wiring the in-report filter itself to recognize both values is left as
future work, tracked by the comment left in `report_template.py` rather than attempted here.

**Verification performed:** `tests/test_legacy_contracts.py` gained a dedicated section
(`ADDITIVE_SELECTORS`, `test_additive_responsible_ai_grc_selectors_are_present`,
`test_legacy_selectors_still_present_alongside_additive_ones`,
`test_additive_selector_does_not_change_the_service_attribute_value`) asserting all of the above in a
single render: every legacy selector and every new one coexist, and `data-service`'s own value is
confirmed to remain literally `"finserv"`, never `"responsible-ai-grc"`.

### 5. CSV filename prefix — implemented, additive only

**Unchanged:** `finserv_security_report_{execution_id}.csv` remains the durable, returned, contractual
object. `tests/test_legacy_contracts.py::test_csv_prefix_is_frozen` and the rewritten
`test_csv_object_name_keeps_the_legacy_prefix` (in `finserv_tests/`) both confirm it.

**Added:** `finserv_assessments/app.py`'s `write_to_s3()` now writes a second, byte-identical object at
`responsible_ai_gov_security_report_{execution_id}.csv` immediately after the legacy write. The second
write is wrapped in its own `try`/`except`; a failure writing it is logged and swallowed, never raised —
the legacy write, which already succeeded by that point, remains the operation callers depend on.

Every reader of the legacy prefix was updated to also read, and deduplicate against, the new one:

- `owasp_assessments/app.py`'s `_read_service_csvs_for_region()` reads both keys when
  `include_finserv=True`, deduplicating by `(Check_ID, Region, Finding)` via a new
  `seen_row_identities` set. The alias key's own absence is **not** reported through `missing_keys` —
  only the legacy key's absence is a real coverage gap, since the two objects are expected to be
  identical, not independently authoritative.
- `generate_consolidated_report/app.py`'s `get_assessment_results()` lists the new prefix (added to the
  S3 paginator's prefix list) and routes any object under it into the **existing** `"finserv"` report
  category — not a new, separate, always-duplicate one. `category_slugs` (the list driving report
  categories) is deliberately left untouched, since it is one-slug-per-category and a naive third slug
  would have created exactly that duplicate category.
- `consolidate_html_reports.py` required **no code change**: its local-disk glob
  (`**/*_security_report_*.csv`) already matches any new `*_security_report_*` prefix generically, and
  its row routing is by `Check_ID` prefix (`FS-` → `finserv`), not by source filename, so rows from the
  new file land in the correct category automatically. Both are pre-existing properties, not something
  added for this item.
- `buildspec.yml`'s `fs_exclude_args` array gained a second `--exclude
  "responsible_ai_gov_security_report_*.csv"` entry, guarded by the same `ENABLE_FINSERV` condition as
  the legacy exclusion (the two prefixes track one enable/disable state, not two independent ones). All
  three existing usage sites picked this up automatically via the array's existing
  `"${fs_exclude_args[@]}"` expansion.

Deduplication in `generate_html_report()` (pre-existing, keyed on
`(Account_ID, output_service, Check_ID, Region, Finding_Details)`) collapses the two identical CSVs into
one logical finding without any change to that function.

**Verification performed:** `tests/test_dual_csv_prefix_routing.py` (new, 3 tests) exercises
`get_assessment_results` end to end with mocked S3, confirming alias-only objects route into the
`finserv` category, both-present objects both route into that same category without creating a
duplicate one, and the rendered HTML report's finding count reflects deduplication (shows `1`, not `2`,
for two identical source rows). `tests/test_fs_exclude_args.py` (new, 4 tests) extracts and executes the
real `fs_exclude_args` shell snippet from `buildspec.yml`, confirming both prefixes are excluded when
disabled, neither is excluded when enabled, and the array shape is correct for AWS CLI argument
expansion. Four new tests were added to `tests/test_owasp_checks.py::TestReadServiceCsvsForRegion`
covering alias-only reads, alias-skipped-when-disabled, deduplication of identical rows across both
prefixes, and preservation of genuinely different rows from each prefix. Two pre-existing tests broken
by the dual-write (`finserv_tests/test_lambda_handler.py::TestWriteToS3::test_writes_csv_to_s3` and
`finserv_tests/test_legacy_contracts.py::test_csv_object_name_keeps_the_legacy_prefix`) were fixed to
assert both writes rather than only the first, plus a new test confirming an alias-write failure never
fails the legacy write.

### 6. Documentation filenames — not implemented, deferred indefinitely

**Current:** `docs/SECURITY_CHECKS_FINSERV.md`, `docs/SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md`,
`docs/SECURITY_CHECKS_FINSERV_SEVERITY_REGISTER.md`. **Unchanged.**

**Why this was not attempted alongside items 1–5:** these three files are published on GitHub Pages and
search-indexed. Renaming one is a **public-URL risk**, categorically different from items 1–3's
internal-identity risk: an external search result or bookmark pointing at
`https://aws-samples.github.io/sample-aiml-security-assessment/docs/SECURITY_CHECKS_FINSERV.html`
returns a 404 the moment the file moves, with no server-side redirect layer available to intercept the
request (GitHub Pages serves static files only). `rebrand-plan.md` section 22.2's no-go criteria already
treat this as a release blocker unless a redirect stub — a minimal HTML file at the old path with
`<meta http-equiv="refresh">` and a visible "this page has moved" notice — is committed in the *same*
change that introduces the new filename.

No redirect-stub infrastructure exists in this repository today, and authoring one correctly (verifying
it actually resolves once published, which requires GitHub Pages to be live, which this local workspace
cannot verify) is out of scope for a workspace that has not been deployed. This item remains deferred
until Stage 2b is actually approved to ship and a real release process exists to publish the redirect
alongside the rename.

### 7. `FS-*` check ID renumbering — not implemented, rejected

**Explicitly rejected**, not merely deferred. `rebrand-plan.md` section 23.1 records "`FS-*`
renumbering: Rejected. Preserve all IDs including `FS-00`" as a resolved decision, not a pending one.
Renumbering would break historical CSV comparison, the 42 OWASP `FS-*` mapping keys, every test
asserting a specific ID, the severity register, and any future Security Hub ASFF export (where `FS-*`
values become `GeneratorId` values per issue #36). Nothing in this implementation touches any `FS-*`
identifier, and nothing should.

### 8. Redundant `aiml-security-` prefix removal — not implemented, rejected for a newly discovered reason

**Current:** the rendered member-account physical name is
`aiml-security-aiml-security-<acct>-RAIGRCAssessment` — the literal `aiml-security-` prefix appears
twice, once from the stack name and once from the `!Sub` expression, wasting 14 of the 64 available
characters. **This document originally proposed dropping the redundant prefix as part of item 1.**

**Why it was not implemented, and should not be without further design work:**
`finserv_assessments/app.py`'s `_self_lambda_name_prefix()` — the mechanism `FS-67`'s self-exclusion
check depends on — derives its comparison prefix by checking
`AWS_LAMBDA_FUNCTION_NAME.startswith("aiml-security-")`. That check is a literal string match, **not**
derived from the CloudFormation stack name or any other runtime-available value. Dropping the
`aiml-security-` prefix from the `FunctionName` `!Sub` expression, as originally proposed, would have
made this check fail for **every sibling assessment Lambda in the same deployment** — not just the
renamed one — silently re-enabling `FS-67` to self-report findings against the assessment's own
infrastructure, the exact false-positive class this mechanism exists to prevent. This risk was not
identified when this document was first drafted; it was found only by reading
`finserv_assessments/app.py` directly before touching the templates.

**What would be required to implement this safely, if ever revisited:** `_self_lambda_name_prefix()`
would need to derive its prefix from something other than a hardcoded literal — for example, deriving
it from `AWS::StackName` (passed as an environment variable) rather than from `AWS_LAMBDA_FUNCTION_NAME`
pattern-matching, or from an explicit tag/naming convention checked against every sibling function's
actual deployed name rather than a string prefix assumption. That is a behavior change to the check
itself, not a rename, and needs its own design and review — it is not bundled into this Stage 2b
implementation.
`tests/test_legacy_contracts.py::test_own_lambda_prefix_matches_self_exclusion_assumption` locks in the
current literal-prefix assumption so a future attempt at this item fails a test immediately if it
forgets to address it first.

## Verification performed across all implemented items

- `tests/test_legacy_contracts.py`: 53 tests, all passing (up from 30 before this branch).
- `finserv_tests/` full suite: 819 tests, all passing.
- `tests/` full suite: 674 tests, all passing (includes `test_dual_csv_prefix_routing.py`,
  `test_fs_exclude_args.py`, and 7 IAM-coverage tests added during live validation — see
  "Live AWS validation" below).
- `cfn-lint` clean on both SAM templates.
- `sam validate --lint` passes both templates.
- `sam build` succeeds for both templates, with the resolved `FunctionName` and logical ID confirmed by
  direct inspection of the build output.
- `ruff check` and `ruff format --check` clean on every new and edited Python file.

## Live AWS validation (post-implementation, real account, single-account template)

Everything above was verified locally — unit tests, `cfn-lint`, `sam validate`/`build`. It was **not**
verified against a real AWS account until a separate round of live testing, performed after the items
above were already implemented and committed. This section records that round, since it found and fixed
a real bug that none of the local verification above could have caught (a static template/test check
cannot detect a permission gap that only surfaces as a runtime `AccessDeniedException`).

**What was done:** `aiml-security-assessment/template.yaml` was built fresh (`sam build`) and deployed via
`sam deploy` directly to a personal AWS sandbox account (bypassing the GitHub-clone/CodeBuild deployment
path entirely, since no CR or push had happened yet). A Step Functions execution was started with both
`enableFinServ` and `enableOWASP` set to `"true"` to exercise every changed code path in one pass
(renamed states, additive selectors, dual CSV write/read/dedup, and OWASP's dependency on the FinServ
CSV). The execution reached `ExecutionSucceeded`, and the execution history confirmed all four renamed
states (`"Responsible AI GRC Enabled?"`, `"Responsible AI GRC Security Assessment"`, etc.) fired
correctly with no old `FinServ`-named states appearing anywhere.

**What that surfaced:** the generated report was downloaded and read row by row, not just checked for a
successful execution status. Two of the 64 FinServ checks (FS-16 ECR image scanning, FS-20 feature store
rollback) reported `COULD NOT ASSESS` due to `AccessDeniedException` on `inspector2:BatchGetAccountStatus`
and (for FS-20, if any feature groups had existed in the test account) would have hit the same failure
mode on `sagemaker:DescribeFeatureGroup`. Root-causing this found the actual gap:
`ResponsibleAIGRCAssessmentFunction`'s own `Policies` block in both `template.yaml` and
`template-multi-account.yaml` never granted either action.
`inspector2:BatchGetAccountStatus` **was** present elsewhere in the same file — granted to
`BedrockSecurityAssessmentFunction`'s policy for its own, unrelated `BR-33` check — which is why
`tests/test_iam_coverage.py`'s existing file-wide grant scan reported the requirement satisfied even
though the function that actually needed it at runtime never received it. This predates Stage 2a/2b (the
grant to the wrong function goes back to the pre-rebrand baseline), but was fixed here rather than left
out of scope, since it was found during this implementation's own live-testing pass.

**The fix:** both actions added to `ResponsibleAIGRCAssessmentFunction`'s own policy block in both SAM
templates (a new `InspectorPermissions` `Sid` for the former, added to the existing `SageMakerPermissions`
`Sid` for the latter). `tests/test_iam_coverage.py` was also fixed, not just the templates: a
resource-scoped `_granted_actions_for_resource()` helper and four new
`test_required_*_actions_are_granted_to_the_*_function` tests now scope the grant scan to one Lambda's
own text block on the SAM templates, so a repeat of "granted somewhere in the file, but not to the
function that needs it" fails the suite directly. A self-test
(`test_resource_scoped_guard_detects_a_grant_on_the_wrong_function`) reproduces the exact bug shape and
asserts the new tests catch it — verified empirically by temporarily reverting the template fix in a
scratch copy and confirming the new test failed before the fix and passed after it. The deployment-layer
wrapper templates (`deployment/1-aiml-security-member-roles.yaml`,
`deployment/aiml-security-single-account.yaml`, `deployment/2-aiml-security-codebuild.yaml`) were checked
and confirmed to use one shared IAM role per template with no per-Lambda separation, so the existing
file-wide scan is already correct there and needed no change.

**Re-verified after the fix**, on the same deployed stack (`sam deploy` as a stack *update*, not a new
stack, then a second Step Functions execution): FS-16 now resolves to a real
`ECR Image Scanning Covered by Inspector Enhanced Scanning` / `Passed` finding (the test account has
Inspector enhanced scanning enabled account-wide) instead of `COULD NOT ASSESS`. A row-by-row diff of the
68-row FinServ CSV between the pre-fix and post-fix executions showed **exactly one row changed** — the
FS-16 row — with all other 67 rows byte-identical, including the dual-written
`responsible_ai_gov_security_report_*.csv` (still byte-identical to the legacy-prefix CSV, MD5-confirmed)
and the OWASP CSV's `OW-03` row that sources its text from FS-16 (confirming the OWASP-reads-FinServ
dependency still works correctly after the fix). The HTML report's Responsible AI GRC metric section
(Failed/Passed/N-A/Total) matched the fixed CSV's counts exactly.

**Found but deliberately not fixed:** a third `AccessDeniedException` appeared, on `BR-08` ("Bedrock
Agent IAM Roles Check", in the separate `BedrockSecurityAssessmentFunction`, unrelated to items 1–5).
Reproducing it directly (`aws bedrock-agent get-agent` against the specific agent ID) showed the actual
error is `kms:Decrypt`/`kms:GenerateDataKey` access denied on a customer-managed KMS key protecting a
pre-existing Bedrock agent in the test account — not a missing IAM *action* grant
(`bedrock:GetAgent` is already granted with `Resource: '*'`). Granting blanket `kms:Decrypt`/
`kms:GenerateDataKey` with `Resource: '*'` would be a materially broader, security-sensitive permission
widening (decrypt access to any KMS key in the account) compared to the narrow, read-only FS-16/FS-20
fixes, and is outside what this round of testing was scoped to change without a separate explicit
decision. The check already degrades gracefully (`N/A`/`Informational`, no crash), so this was left
as-is and is recorded here for visibility rather than fixed silently.

## What this document does not claim

- It does not claim Stage 2a has run in production, or that any Stage 2b precondition from
  `rebrand-plan.md` section 21.2 is now met. Those preconditions are about production validation and
  explicit sign-off, neither of which a local implementation can satisfy.
- It does not claim a CR, GitHub issue, or PR exists for any of this. None do.
- It does not claim items 4–5's additive selectors and CSV prefix are wired into every possible
  consumer — specifically, the in-report client-side filter dropdown for item 4 was deliberately left
  unwired, as explained in that section.

## Next steps (require explicit approval before proceeding to a merge or deployment)

1. Confirm Stage 2a has been running in production for at least one full deployment cycle with no
   reported `EnableFinServAssessment` / `EnableResponsibleAIGovAssessment` conflicts.
2. Obtain and record explicit sign-off that items 1–5 as implemented on this branch are approved to
   proceed toward review — this local implementation is not that sign-off.
3. Draft the deprecation-period customer communication and rollback rehearsal specifically for items
   1–3 (the breaking identity/state-name changes), since items 4–5 are additive and need neither.
4. Decide whether item 8 is worth pursuing as its own, separately-designed change to
   `_self_lambda_name_prefix()`'s derivation logic — it is not a prerequisite for items 1–5 and should
   not block them.
5. Decide whether and when item 6 (documentation filename renames with redirect stubs) is worth pursuing
   — it has no dependency on items 1–5 and can be sequenced independently.
6. Only after 1–2, open a CR for review.
