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
- Expanded the AgentCore assessment to inventory AWS Agent Registry resources
  and records using the generally available control-plane APIs.
- Added end-user guidance for determining whether an upgrade requires only a
  CodeBuild run, a top-level infrastructure stack update, or a multi-account
  member-role StackSet update.

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
  dependencies, AWS SAM templates, state machine inputs, and build
  orchestration.
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
