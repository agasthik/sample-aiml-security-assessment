# Migrating to the Responsible AI GRC parameter name

`EnableResponsibleAIGRCAssessment` is now the primary parameter for the Responsible AI GRC
(`FS-01` through `FS-69`) checks. `EnableFinServAssessment` — the original name, tied to the
"FinServ" branding this project has moved away from — is retained as a legacy alias so existing
stacks and automation that reference it keep working.

## Nothing breaks if you do nothing

Updating your stack to a template version that includes this rename, without changing any
parameter values, has no effect. If you previously set `EnableFinServAssessment`, that value
keeps controlling whether the FS-01 through FS-69 checks run: `EnableFinServAssessment` defaults
to a special sentinel value, `"__UNSET__"`, meaning "deliberately not set", which defers entirely
to `EnableResponsibleAIGRCAssessment` — the new primary parameter, which defaults to plain
`"false"`.

## Why two parameters exist for one toggle

`EnableFinServAssessment` is the original name. `EnableResponsibleAIGRCAssessment` is the current
name and the one new deployments should use. Both control the exact same 64 checks (`FS-01`
through `FS-69`, less five IDs merged into other services — see `docs/RESPONSIBLE_AI_GRC_SCOPE.md`
for the full count reconciliation). Neither behaves differently: no check behavior, report
content, or CSV output differs based on which parameter you use.

## How the two parameters interact

| Your situation | What to do | What happens |
|---|---|---|
| You've never touched either parameter | Nothing | Checks stay off (both default to off) |
| You already have `EnableFinServAssessment=true` and want to keep going | Nothing | Checks stay on, unchanged |
| You are deploying fresh, or want to move to the current name | Set `EnableResponsibleAIGRCAssessment` to `"true"` or `"false"` explicitly | This is now the primary toggle |
| You set both, and they agree | Nothing needed, but no harm if you do | Works normally |
| You set both, and they *disagree*, and the legacy one is explicitly `"true"` | **Stop and pick one value** | The deployment fails fast with an explicit error naming both parameters, before any checks run |

The one case this deliberately refuses to guess at is the last row: if `EnableFinServAssessment`
is explicitly `"true"` and `EnableResponsibleAIGRCAssessment` explicitly disagrees, the CodeBuild
job exits with an error rather than silently picking one value. This is intentional — a
silently-resolved conflict here would mean either running checks a customer thought they'd
disabled, or skipping checks a customer thought they'd enabled, and both are worse than a build
failure with a clear message.

If you see this error, fix it by setting both parameters to the same value (or clearing
`EnableFinServAssessment` back to `"__UNSET__"` to defer to the primary one).

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
