# Migrating to the Responsible AI GRC parameter name

`EnableResponsibleAIGRCAssessment` is now the primary parameter for the Responsible AI GRC
(`FS-01` through `FS-69`) checks. `EnableFinServAssessment` — the original name, tied to the
"FinServ" branding this project has moved away from — is retained as a legacy alias so existing
stacks and automation that reference it keep working.

## The toggle behavior doesn't change if you do nothing

Updating your stack to a template version that includes this rename, without changing any
parameter values, does not change whether the checks run. If you previously set
`EnableFinServAssessment`, that value keeps controlling whether the FS-01 through FS-69 checks
run: `EnableFinServAssessment` defaults to a special sentinel value, `"__UNSET__"`, meaning
"deliberately not set", which defers entirely to `EnableResponsibleAIGRCAssessment` — the new
primary parameter, which defaults to plain `"false"`.

This is specifically about the toggle. Something else genuinely does change regardless of which
parameter you use — the S3 object name of the CSV report — covered in
[What does change: the CSV object name has no alias](#what-does-change-the-csv-object-name-has-no-alias)
below.

## Why two parameters exist for one toggle

`EnableFinServAssessment` is the original name. `EnableResponsibleAIGRCAssessment` is the current
name and the one new deployments should use. Both control the exact same 64 checks (`FS-01`
through `FS-69`, less five IDs merged into other services — see `docs/RESPONSIBLE_AI_GRC_SCOPE.md`
for the full count reconciliation), and neither parameter *choice* changes what the checks find:
which of the two names you use to turn FS-01 through FS-69 on or off has no effect on check
behavior or report content. It is not a claim that nothing about the CSV changed — see
[What does change](#what-does-change-the-csv-object-name-has-no-alias) below for the one thing
that did, independent of which parameter you use.

## How the two parameters interact

| Your situation | What to do | What happens |
|---|---|---|
| You've never touched either parameter | Nothing | Checks stay off (both default to off) |
| You already have `EnableFinServAssessment=true` and want to keep going | Nothing | Checks stay on, unchanged |
| You are deploying fresh, or want to move to the current name | Set `EnableResponsibleAIGRCAssessment` to `"true"` or `"false"` explicitly | This is now the primary toggle |
| You set the legacy alias, and leave the primary at its `"false"` default | Nothing needed | The legacy alias silently wins — this is the "keep going" row above, generalized |
| You set both, and they agree | Nothing needed, but no harm if you do | Works normally |
| You set the primary explicitly to `"true"`, and the legacy alias explicitly disagrees | **Stop and pick one value** | The deployment fails fast with an explicit error naming both parameters, before any checks run |

The one case this deliberately refuses to guess at is the last row: if
`EnableResponsibleAIGRCAssessment` is explicitly `"true"` and `EnableFinServAssessment` is
explicitly set to anything else, the CodeBuild job exits with an error rather than silently
picking one value. This is intentional — a silently-resolved conflict here would mean either
running checks a customer thought they'd disabled, or skipping checks a customer thought they'd
enabled, and both are worse than a build failure with a clear message.

This check is one-directional, not symmetric. Because `EnableResponsibleAIGRCAssessment` always
materializes a value in CloudFormation (there is no way to tell "left at its default" apart from
"explicitly set to false" at the CFN layer), the primary value being `"false"` is treated as "not
yet opined" rather than a conflicting explicit choice — so the legacy alias is still allowed to
win in that case (the row above this one). The build only ever fails when the *primary* is
explicitly `"true"` and the alias disagrees; setting the primary explicitly to `"false"` while
the legacy alias says `"true"` does not fail, it just resolves to the legacy alias's value.

If you see this error, fix it by setting both parameters to the same value (or clearing
`EnableFinServAssessment` back to `"__UNSET__"` to defer to the primary one).

## Scope of the alias: CloudFormation and CodeBuild only, not the Step Functions execution input

Everything above describes `EnableFinServAssessment` (the CloudFormation parameter) and
`ENABLE_FINSERV` (the CodeBuild environment variable it becomes). `buildspec.yml` resolves
whichever of those you set into a single effective value and passes it to Step Functions as
`"enableResponsibleAIGRC"` in the `StartExecution` input — there is no `"enableFinServ"` key in
that input, aliased or otherwise.

If you deploy and run assessments through the provided CodeBuild templates
(`deployment/aiml-security-single-account.yaml`, `deployment/2-aiml-security-codebuild.yaml`),
this distinction is invisible to you: CodeBuild always calls `StartExecution` with the resolved
`enableResponsibleAIGRC` value, never with `enableFinServ`.

It matters only if something calls `StartExecution` directly — bypassing CodeBuild and
`buildspec.yml` — using the pre-rebrand input shape `{"enableFinServ": "true"}`. That input is
rejected: the execution fails immediately with error `LegacyEnableFinServInputRejected` rather
than silently skipping the Responsible AI GRC checks. Use `"enableResponsibleAIGRC": "true"` (or
`"enableOWASP": "true"`) in the execution input instead. See
[Troubleshooting §6b](TROUBLESHOOTING.md#6b-execution-fails-immediately-with-legacyenablefinservinputrejected).

## What does change: the CSV object name has no alias

Everything above is about which *parameter name* turns the checks on or off — none of it changes
what those checks produce. One thing genuinely does change, and it is not covered by any alias:
**the S3 object name of the raw CSV report.**

The assessment Lambda's `write_to_s3()` now writes a single object named
`responsible_ai_grc_security_report_{execution_id}.csv`. The original name,
`finserv_security_report_{execution_id}.csv`, is retired — not aliased, not dual-written. An
earlier point in this rebrand's history (Phase 2 Stage 2b) briefly wrote both the legacy name and
an additive `responsible_ai_gov_security_report_{execution_id}.csv` name side by side; that
dual-write was itself removed before this rename, so there has never been a version of this
project that writes the legacy CSV name alongside the current one.

This matters if you have automation that reads the CSV directly from S3 by its exact key —
polling for `finserv_security_report_*.csv`, or hardcoding that prefix in a downstream ETL job,
for example. That automation will find nothing for any assessment run against a template version
that includes this rename; there is no alias to fall back to. It must be updated to look for
`responsible_ai_grc_security_report_*.csv` instead.

Two things are unaffected by this:

- **The HTML report and its content.** The report layer's own CSV-discovery glob
  (`consolidate_html_reports.py`'s `**/*_security_report_*.csv`) already matches any
  `*_security_report_*` prefix generically, so the consolidated HTML report is unaffected by this
  rename — it finds the CSV under its new name automatically.
- **Archived CSVs already written under the old name.** Those are not rewritten or deleted; only
  the object name a *new* assessment run produces going forward has changed.

See [Responsible AI GRC — scope, sources, and compatibility](RESPONSIBLE_AI_GRC_SCOPE.md#compatibility-policy)
for the complete list of every other machine identity this rebrand renamed outright (CSS classes,
DOM slug, Step Functions state names, the CloudFormation logical ID and physical Lambda name) —
none of those has an alias either, for the same reason: they were reviewed, declared breaking
changes, not undeclared ones.

## What you do NOT need to do

- You do not need to migrate immediately. There is no removal timeline for
  `EnableFinServAssessment` — it is a permanent compatibility contract.
- You do not need to update any automation that reads `EnableFinServAssessment` from a
  `describe-stacks` call — that parameter still exists, still has its original name, and still
  holds the effective value that was actually used for that deployment (the resolution happens
  inside the CodeBuild job, not at the CloudFormation parameter level, so `describe-stacks` on the
  deployment templates shows exactly what you set, not a resolved value).

## Verifying which value actually took effect

The CodeBuild build log for your deployment prints the resolved value explicitly, regardless of
which parameter (or both) you set. Look for this line in the `build` phase log:

```
Responsible AI GRC assessment enabled is true
```

(or `false`). If you set the legacy alias, you'll also see one of these two lines immediately
above it, confirming which precedence path was taken:

```
ENABLE_FINSERV not set; using ENABLE_RESPONSIBLE_AI_GRC (false)
```

or

```
ENABLE_FINSERV set to true; overriding the effective Responsible AI GRC toggle
```
