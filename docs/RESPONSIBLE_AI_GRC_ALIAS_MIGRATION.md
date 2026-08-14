# Migrating to the Responsible AI GRC parameter alias (Phase 2, Stage 2a)

This guide covers the additive `EnableResponsibleAIGovAssessment` parameter introduced alongside the
existing `EnableFinServAssessment` parameter. It is written for customers who have already deployed
this solution and are updating their stack, and for anyone reading the CloudFormation console asking
"why are there two parameters that both say Responsible AI GRC / Financial Services checks?"

If you have not yet deployed this solution, you can ignore this guide and use either parameter — they
do the same thing.

## Nothing breaks if you do nothing

Updating your stack to a template version that includes this alias, without changing any parameter
values, has no effect. `EnableFinServAssessment` keeps its current value and keeps controlling whether
the FS-01 through FS-69 checks run. `EnableResponsibleAIGovAssessment` defaults to a special value,
`"__UNSET__"`, which means "deliberately not set" and defers entirely to `EnableFinServAssessment`.

## Why two parameters exist for one toggle

`EnableFinServAssessment` is the original name, tied to the "FinServ" branding this project is moving
away from. `EnableResponsibleAIGovAssessment` is the new name, tied to the "Responsible AI GRC"
branding. Both control the exact same 64 checks (`FS-01` through `FS-69`, less five IDs merged into
other services — see `docs/RESPONSIBLE_AI_GRC_SCOPE.md` for the full count reconciliation). Neither is
being removed in this release. This is intentionally the *only* change in this release: no check
behavior, report content, or CSV output differs based on which parameter you use.

## How the two parameters interact

| Your situation | What to do | What happens |
|---|---|---|
| You've never touched either parameter | Nothing | Checks stay off (both default to off) |
| You already have `EnableFinServAssessment=true` and want to keep going | Nothing | Checks stay on, unchanged |
| You want to start using the new name going forward | Set `EnableResponsibleAIGovAssessment` to `"true"` or `"false"` explicitly | The alias value takes over as the effective toggle |
| You set both, and they agree | Nothing needed, but no harm if you do | Works normally |
| You set both, and they *disagree*, and the legacy one is explicitly `"true"` | **Stop and pick one value** | The deployment fails fast with an explicit error naming both parameters, before any checks run |

The one case this deliberately refuses to guess at is the last row: if `EnableFinServAssessment` is
explicitly `"true"` and `EnableResponsibleAIGovAssessment` explicitly disagrees, the CodeBuild job exits
with an error rather than silently picking one value. This is intentional — a silently-resolved
conflict here would mean either running checks a customer thought they'd disabled, or skipping checks a
customer thought they'd enabled, and both are worse than a build failure with a clear message.

If you see this error, fix it by setting both parameters to the same value (or clearing
`EnableResponsibleAIGovAssessment` back to `"__UNSET__"` to defer to the legacy one).

## What you do NOT need to do

- You do not need to migrate immediately. There is no deprecation timeline for
  `EnableFinServAssessment` in this release — see `docs/RESPONSIBLE_AI_GRC_PHASE2_STAGE2B_DESIGN.md`
  for what a future major-release change to remove it would require, which has not been scheduled.
- You do not need to update any automation that reads `EnableFinServAssessment` from a
  `describe-stacks` call — that parameter still exists, still has its original name, and still holds
  the effective value that was actually used for that deployment (the resolution happens inside the
  CodeBuild job, not at the CloudFormation parameter level, so `describe-stacks` on the deployment
  templates shows exactly what you set, not a resolved value).
- Nothing in the generated report, the CSV filenames, the report's HTML selectors, or the Step
  Functions state names changes as part of this alias. All of that is out of scope for this stage —
  see `docs/RESPONSIBLE_AI_GRC_PHASE2_STAGE2B_DESIGN.md`.

## Verifying which value actually took effect

The CodeBuild build log for your deployment prints the resolved value explicitly, regardless of which
parameter (or both) you set. Look for this line in the `build` phase log:

```
FinServ / Responsible AI GRC assessment enabled is true
```

(or `false`). If you set the alias, you'll also see one of these two lines immediately above it,
confirming which precedence path was taken:

```
ENABLE_RESPONSIBLE_AI_GOV not set; using ENABLE_FINSERV (false)
```

or

```
ENABLE_RESPONSIBLE_AI_GOV set to true; overriding the effective FinServ/Responsible-AI-GRC toggle
```

## Archived reports from before this change

Every report generated before this alias existed used only `EnableFinServAssessment`. Nothing about
those reports — their CSVs, their HTML, their filenames — is affected retroactively. There is currently
no second CSV filename prefix to reconcile (see the next section), so there is nothing for an archived
report converter to actually convert yet.

## The converter utility

`scripts/convert_finserv_csv_prefix.py` exists ahead of need. It is a read-only utility that can list
and diff assessment CSVs across two candidate S3 key prefixes for a given execution ID, intended for
the day a second CSV prefix (for example `responsible_ai_gov_security_report_*.csv`) is actually
approved and introduced in a Stage 2b change. It does not run against any prefix change today because
none exists — running it now against a deployment that only ever wrote `finserv_security_report_*.csv`
will correctly report that there is nothing to reconcile.
