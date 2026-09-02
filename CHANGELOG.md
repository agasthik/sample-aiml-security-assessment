# Changelog

All notable user-facing and deployable changes to this project are documented
in this file.

Changes are accumulated under **Unreleased** as they are merged. Creating a
release is not required for every change. When a version is tagged, move its
entries into a dated version section and create a new empty **Unreleased**
section.

## Unreleased

### Added

- Added professional PDF reports for both single-account and multi-account
  assessments. PDFs include a deterministic executive section covering
  direct-control posture, broad control themes, priority improvements, and
  assessment-area results, followed by all passed, failed, and N/A findings
  with account, region, resource detail, remediation, and references.
- PDF reports add deterministic analysis derived only from the findings
  themselves: severity mix and failed-row charts by assessment area and control
  theme, per-account scorecards, prevalence labelling that separates systemic
  gaps from isolated ones, grouping of findings that share a single remediation
  action, a breakdown of why rows were reported as N/A, catalog coverage per
  assessment area, and compliance-framework and OWASP category rollups. No
  finding text, severity, or status is inferred or re-scored.
- PDF reports are now navigable, with a contents page and matching PDF
  bookmarks, and repeated findings are grouped by check across accounts and
  regions so multi-account reports no longer restate near-identical rows.
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

- Shared normalized report inputs between the HTML and PDF renderers so
  service routing, deduplication, contextual Agentic/OWASP treatment, account
  scope, and region scope remain consistent across formats.
- Updated CodeBuild report collection to install the PDF renderer dependency
  and copy PDF artifacts into the customer-facing report bucket.
- Standardized all AWS SDK dependencies on exact `boto3==1.43.85` and
  `botocore==1.43.85` pins.
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

- Evaluate attached customer-managed IAM policy documents as well as inline
  policies when checking AgentCore and Agent Registry wildcard access.
- Preserve registry client initialization and API failures as indeterminate
  assessment results instead of reporting them as regional unavailability.
- Provide error-specific remediation for registry list and detail failures.
- Preserve case-insensitive wildcard matching while supporting embedded and
  partial wildcard action patterns.
- Avoid unnecessary per-record registry detail calls and add timeout guards to
  registry inventory and check processing.

### Deployment impact

- **CodeBuild run required** to build and deploy the updated assessment code,
  PDF dependency, AWS SAM templates, state machine inputs, and build
  orchestration. The run begins generating paired HTML and PDF reports.
- **Single-account infrastructure update required** because
  `deployment/aiml-security-single-account.yaml` changed.
- **Multi-account member-role StackSet update required first** because
  `deployment/1-aiml-security-member-roles.yaml` changed with the Agent
  Registry permissions required by the new checks.
- **Multi-account central infrastructure update required** because
  `deployment/2-aiml-security-codebuild.yaml` changed.
- Deployments pinned to a tag or commit must update the `GitHubBranch`
  CloudFormation parameter to the revision containing these changes before
  starting CodeBuild.

## 1.0.0 - 2026-07-10

- Initial tagged release.
