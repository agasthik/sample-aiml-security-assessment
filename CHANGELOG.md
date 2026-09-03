# Changelog

All notable user-facing and deployable changes to this project are documented
in this file.

Changes are accumulated under **Unreleased** as they are merged. Creating a
release is not required for every change. When a version is tagged, move its
entries into a dated version section and create a new empty **Unreleased**
section.

## Unreleased

### Added

- Added six AWS Agent Registry security checks (`AC-18` through `AC-23`) for
  publication approval, discovery authorization, customer-managed encryption,
  organization auto-detection, record lifecycle, and provenance.
- Added the corresponding Agentic AI Security mappings (`AG-33` through
  `AG-38`), increasing the catalog from 194 to 206 checks.
- Added configurable `RequireAgentRegistryManualApproval` and
  `RequireAgentRegistryCMK` deployment baselines.
- Added SDK contract, IAM coverage, baseline-wiring, registry inventory,
  error-path, and finding-behavior tests.

### Changed

- Standardized all AWS SDK dependencies on exact `boto3==1.43.85` and
  `botocore==1.43.85` pins.
- Split the multi-account member role's assessment grants into customer-managed
  policies and added a rendered-policy size guard, preventing StackSet
  deployment failures as IAM permissions grow.
- Expanded the AgentCore assessment to inventory AWS Agent Registry resources
  and records using the generally available control-plane APIs.
- Added end-user guidance for determining whether an upgrade requires only a
  CodeBuild run, a top-level infrastructure stack update, or a multi-account
  member-role StackSet update.
- Updated the screenshot capture tool to enforce the repository-root `.venv`,
  install its optional Python dependencies when missing, and verify a
  venv-local Playwright Chromium browser before capturing screenshots. Capture
  height now expands dynamically so every left-navigation section is visible.

### Fixed

- Treat absent optional Agent Registry AC-23 creator attribution, provenance,
  and provenance source-type metadata as indeterminate N/A findings instead of
  false failures, and keep reporting a mismatched lineage as failed even when
  another provenance entry omits its source type.
- Report an Agent Registry registry that omits the optional
  `approvalConfiguration` as an AC-18 informational N/A instead of passing a
  manual-approval control that was never observed.
- Restrict AC-02 wildcard findings and AC-03 stale-access discovery to explicit
  `bedrock-agentcore` and `agent-registry` IAM action namespaces so generic
  administrator policies are not misreported as AgentCore-specific grants.
- Stop AC-03 IAM last-access polling before the Lambda timeout, preserve
  completed results with an explicit incomplete-assessment row, and classify
  IAM job timeouts as indeterminate instead of failed controls.
- Require AC-03 candidate permissions to come from attached or inline policy
  documents instead of inferring access from attached-policy names.
- Bound Agent Registry record inventory to 1,000 records, stop registry and
  record pagination before the Lambda timeout, surface partial inventories as
  `N/A`/Informational, and backfill deadline-skipped AgentCore and Agentic AI
  checks before writing the regional CSV.
- Make AC-18 auto-approval remediation conditional on the configured baseline
  so advisory findings do not instruct operators to enable manual approval.
- Evaluate `Allow`/`NotAction` allow-except policies in AC-02 and AC-03 only
  when their exclusions name an AgentCore or Agent Registry namespace without
  fully covering both, so an administrator-style grant is scored the same
  whether it is written as `Action: "*"` or as `NotAction`.
- Describe an absent AC-19 discovery authorization configuration as
  unconfigured rather than as an unrecognized authorizer type.
- Treat AC-19 IAM and constrained JWT authorizer configurations as
  informational evidence requiring access review instead of reporting a High
  pass without establishing intended callers.
- Make screenshot capture failures, including clipped-sidebar guard failures,
  terminate the capture tool with a non-zero exit status.
- Calculate report pass rates from unique direct-service controls instead of
  resource-row counts: any failed assessable row fails its `Check_ID`, controls
  pass only when all assessable rows pass, and N/A rows are excluded.
- Make AC-22 lifecycle-state observations Informational/N/A until the check
  defines a genuine noncompliant lifecycle state.
- Evaluate attached customer-managed IAM policy documents as well as inline
  policies when checking AgentCore and Agent Registry wildcard access.
- Preserve registry client initialization and API failures as indeterminate
  assessment results instead of reporting them as regional unavailability.
- Provide error-specific remediation for registry list and detail failures.
- Report AgentCore and Agent Registry as unavailable in regions the account has
  not enabled. A missing regional endpoint and the credential-shaped codes AWS
  returns for a disabled region (`UnrecognizedClientException`,
  `InvalidClientTokenId`, `AuthFailure`) are classified as regional
  unavailability, so scanning all partition regions no longer produces
  per-region rows advising operators to troubleshoot DNS, VPC routing, or
  credentials.
- Preserve genuinely expired or malformed credentials (`ExpiredToken`,
  `SignatureDoesNotMatch`) and other API failures as incomplete assessments
  with credential- or error-specific remediation.
- Require AC-23 auto-detected provenance source ARNs to use the AgentCore
  service and a runtime or gateway resource matching the declared source type.
- Preserve case-insensitive wildcard matching while supporting embedded and
  partial wildcard action patterns.
- Avoid unnecessary per-record registry detail calls and add timeout guards to
  registry inventory and check processing.

### Deployment impact

- **CodeBuild run required** to build and deploy the updated assessment code,
  dependencies, AWS SAM templates, and build orchestration.
- **Single-account infrastructure update required** because
  `deployment/aiml-security-single-account.yaml` changed.
- **Multi-account member-role StackSet update required first** because
  `deployment/1-aiml-security-member-roles.yaml` changed with the Agent
  Registry permissions required by the new checks and now creates the
  customer-managed member-role policies.
- **Multi-account central infrastructure update required** because
  `deployment/2-aiml-security-codebuild.yaml` changed.
- Deployments pinned to a tag or commit must update the `GitHubBranch`
  CloudFormation parameter to the revision containing these changes before
  starting CodeBuild.

## 1.0.0 - 2026-07-10

- Initial tagged release.
