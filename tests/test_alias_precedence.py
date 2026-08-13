"""Phase 2 Stage 2a — EnableResponsibleAIGovAssessment alias precedence.

These tests execute the *actual* shell snippet from buildspec.yml (extracted
verbatim, not reimplemented) in a real bash subprocess, so a future edit to
the buildspec's alias-resolution block is exercised by this suite rather than
silently diverging from it.

Precedence contract (rebrand-plan.md, section 18.3, Stage 2a):

    | New value (alias)  | Legacy value (ENABLE_FINSERV) | Effective result |
    |---------------------|--------------------------------|-------------------|
    | Absent (__UNSET__)  | Absent (default "false")       | "false"           |
    | Absent (__UNSET__)  | "true" / "false"               | legacy value      |
    | "true" / "false"    | Absent (default "false")       | alias value       |
    | Both, equal         | Same                            | shared value      |
    | Both, different     | legacy explicitly "true"        | explicit failure  |

CloudFormation can never produce a truly *absent* legacy value -- FS always
materializes its "false" default -- so "legacy absent" and "legacy explicitly
false" are the same wire value. The precedence logic therefore only rejects a
conflict when the legacy value is explicitly "true" and the alias disagrees.
"""

import os
import subprocess

import pytest
import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILDSPEC_PATH = os.path.join(REPO_ROOT, "buildspec.yml")


def _load_alias_resolution_script():
    """Extract the ENABLE_FINSERV normalization + alias-precedence commands
    verbatim from buildspec.yml's build phase, in file order.

    buildspec.yml has no CloudFormation intrinsics, so a plain yaml.safe_load
    is sufficient here (unlike the deployment/ and SAM templates elsewhere in
    this test suite, which need the intrinsic-tolerant loader).
    """
    with open(BUILDSPEC_PATH) as handle:
        data = yaml.safe_load(handle)
    commands = data["phases"]["build"]["commands"]

    normalize_cmd = None
    alias_cmd = None
    for command in commands:
        if command.strip().startswith('export ENABLE_FINSERV="$(echo'):
            normalize_cmd = command
        elif "Phase 2 Stage 2a" in command and "ENABLE_RESPONSIBLE_AI_GOV" in command:
            alias_cmd = command

    assert normalize_cmd is not None, (
        "Could not find the ENABLE_FINSERV normalization command in "
        "buildspec.yml -- has it moved or been reworded?"
    )
    assert alias_cmd is not None, (
        "Could not find the Phase 2 Stage 2a alias-precedence command in "
        "buildspec.yml -- has it moved or been reworded?"
    )
    return normalize_cmd + "\n" + alias_cmd


_ALIAS_SCRIPT = _load_alias_resolution_script()


def _run_alias_resolution(env_overrides):
    """Run the extracted script in bash with the given env vars set, and
    return (exit_code, effective_ENABLE_FINSERV_or_None, stdout, stderr).

    Only the variables in env_overrides are set; anything not passed is left
    genuinely absent from the subprocess environment (not merely empty), to
    faithfully reproduce "customer never set this CodeBuild env var".
    """
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    env.update(env_overrides)
    script = (
        _ALIAS_SCRIPT
        + '\necho "RESOLVED_ENABLE_FINSERV=${ENABLE_FINSERV-__UNSET_SENTINEL__}"\n'
    )
    result = subprocess.run(
        ["bash", "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    resolved = None
    for line in result.stdout.splitlines():
        if line.startswith("RESOLVED_ENABLE_FINSERV="):
            resolved = line.split("=", 1)[1]
            if resolved == "__UNSET_SENTINEL__":
                resolved = None
    return result.returncode, resolved, result.stdout, result.stderr


class TestAliasPrecedence:
    def test_both_absent_defaults_to_false(self):
        code, resolved, _, _ = _run_alias_resolution({})
        assert code == 0
        assert resolved == "false"

    @pytest.mark.parametrize("legacy_value", ["true", "false", "TRUE", "False"])
    def test_alias_absent_legacy_present_uses_legacy(self, legacy_value):
        code, resolved, _, _ = _run_alias_resolution({"ENABLE_FINSERV": legacy_value})
        assert code == 0
        assert resolved == legacy_value.lower()

    @pytest.mark.parametrize("alias_value", ["true", "false", "TRUE", "False"])
    def test_alias_present_legacy_absent_uses_alias(self, alias_value):
        # Legacy absent is indistinguishable on the wire from legacy's own
        # "false" default -- CodeBuild always materializes ENABLE_FINSERV.
        # Simulate the true "customer never touched EnableFinServAssessment"
        # case as ENABLE_FINSERV genuinely unset in the subprocess env.
        code, resolved, _, _ = _run_alias_resolution(
            {"ENABLE_RESPONSIBLE_AI_GOV": alias_value}
        )
        assert code == 0
        assert resolved == alias_value.lower()

    @pytest.mark.parametrize("alias_value", ["true", "false"])
    def test_alias_present_legacy_at_default_uses_alias(self, alias_value):
        # Legacy explicitly re-asserts its own default ("false") -- this is
        # the value CloudFormation actually sends when a customer leaves
        # EnableFinServAssessment untouched. Alias must still win.
        code, resolved, _, _ = _run_alias_resolution(
            {"ENABLE_FINSERV": "false", "ENABLE_RESPONSIBLE_AI_GOV": alias_value}
        )
        assert code == 0
        assert resolved == alias_value

    def test_both_present_and_equal_shares_value(self):
        code, resolved, _, _ = _run_alias_resolution(
            {"ENABLE_FINSERV": "true", "ENABLE_RESPONSIBLE_AI_GOV": "true"}
        )
        assert code == 0
        assert resolved == "true"

    def test_both_present_agree_on_false(self):
        code, resolved, _, _ = _run_alias_resolution(
            {"ENABLE_FINSERV": "false", "ENABLE_RESPONSIBLE_AI_GOV": "false"}
        )
        assert code == 0
        assert resolved == "false"

    def test_both_present_and_conflicting_fails_explicitly(self):
        code, resolved, stdout, _ = _run_alias_resolution(
            {"ENABLE_FINSERV": "true", "ENABLE_RESPONSIBLE_AI_GOV": "false"}
        )
        assert code != 0
        assert "ERROR" in stdout
        assert "EnableFinServAssessment" in stdout
        assert "EnableResponsibleAIGovAssessment" in stdout

    def test_conflict_detection_is_case_insensitive(self):
        code, _, stdout, _ = _run_alias_resolution(
            {"ENABLE_FINSERV": "true", "ENABLE_RESPONSIBLE_AI_GOV": "FALSE"}
        )
        assert code != 0
        assert "ERROR" in stdout

    def test_explicit_unset_sentinel_behaves_like_absent(self):
        # The CloudFormation parameter's own default value literal must be
        # treated identically to a shell-level absent alias.
        code, resolved, _, _ = _run_alias_resolution(
            {"ENABLE_FINSERV": "true", "ENABLE_RESPONSIBLE_AI_GOV": "__UNSET__"}
        )
        assert code == 0
        assert resolved == "true"


class TestMixedDeploymentVersionSkew:
    """The ASL is untouched by Stage 2a (see rebrand-plan.md section 18.3), so
    the classic four-way old/new buildspec x old/new ASL matrix collapses:
    there is only one ASL, and it never sees the alias -- it only ever reads
    the single `enableFinServ` Step Functions input key, which is resolved
    upstream of `start-execution`.

    The two skews this repo *can* actually produce are both about the
    deployment-layer CloudFormation template and buildspec.yml being fetched
    and deployed independently (the CFN template is deployed once, out of
    band, by the customer; buildspec.yml is pulled fresh from GitHub on every
    CodeBuild run):

    1. Old CFN template (predates EnableResponsibleAIGovAssessment) + new
       buildspec.yml -- the CodeBuild project simply never defines
       ENABLE_RESPONSIBLE_AI_GOV, so it is genuinely absent from the build
       environment. Already covered by every "absent" case above; asserted
       again here under this name for direct traceability to the scenario.
    2. New CFN template (defines the alias, defaulted to "__UNSET__") + old
       buildspec.yml (predates the alias-resolution block entirely, so it
       never reads ENABLE_RESPONSIBLE_AI_GOV at all) -- the alias parameter
       is silently inert until the customer's CodeBuild project also picks
       up the new buildspec. This must never crash or change the legacy
       ENABLE_FINSERV-only behavior.
    """

    def test_old_template_new_buildspec_alias_genuinely_absent(self):
        # Scenario 1: no ENABLE_RESPONSIBLE_AI_GOV in the environment at all
        # (not even empty-string) -- exactly what an old CFN template's
        # CodeBuild project produces when it has never heard of this alias.
        code, resolved, _, _ = _run_alias_resolution({"ENABLE_FINSERV": "true"})
        assert code == 0
        assert resolved == "true"
        assert "ENABLE_RESPONSIBLE_AI_GOV" not in os.environ

    def test_new_template_old_buildspec_alias_is_inert_if_unread(self):
        # Scenario 2: simulate an old buildspec.yml by running ONLY the
        # legacy normalization line (never invoking the alias-resolution
        # block at all, since an old buildspec doesn't contain it). The
        # CFN-provided alias value must have zero effect -- proving that a
        # stack update to the new template does not require simultaneously
        # updating buildspec.yml for existing behavior to keep working.
        legacy_only_script = (
            'export ENABLE_FINSERV="$(echo "${ENABLE_FINSERV:-false}" | '
            "tr '[:upper:]' '[:lower:]')\"\n"
            'echo "RESOLVED_ENABLE_FINSERV=${ENABLE_FINSERV}"\n'
        )
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "ENABLE_FINSERV": "false",
            "ENABLE_RESPONSIBLE_AI_GOV": "true",
        }
        result = subprocess.run(
            ["bash", "-c", legacy_only_script],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        resolved = [
            line.split("=", 1)[1]
            for line in result.stdout.splitlines()
            if line.startswith("RESOLVED_ENABLE_FINSERV=")
        ][0]
        # An old buildspec that never reads the alias must fall through to
        # the legacy value untouched, not error and not silently adopt the
        # alias by accident.
        assert resolved == "false"


class TestCloudFormationAliasParameters:
    """Confirm the alias parameter is wired identically in both deployment
    templates: same AllowedValues/Default, same sentinel, and appended after
    the existing environment variables (never reordering environment-variable
    index [0], which the EventBridge InputTransformer reads positionally)."""

    _TEMPLATES = [
        os.path.join(REPO_ROOT, "deployment", "2-aiml-security-codebuild.yaml"),
        os.path.join(REPO_ROOT, "deployment", "aiml-security-single-account.yaml"),
    ]

    @pytest.mark.parametrize("template_path", _TEMPLATES)
    def test_alias_parameter_declared_with_unset_sentinel(self, template_path):
        with open(template_path) as handle:
            text = handle.read()
        assert "EnableResponsibleAIGovAssessment:" in text
        assert '["true", "false", "__UNSET__"]' in text
        assert 'Default: "__UNSET__"' in text

    @pytest.mark.parametrize("template_path", _TEMPLATES)
    def test_bucket_report_env_var_still_occupies_index_zero(self, template_path):
        with open(template_path) as handle:
            text = handle.read()
        env_block_start = text.index("EnvironmentVariables:")
        first_name_pos = text.index("- Name:", env_block_start)
        line = text[first_name_pos : first_name_pos + 40]
        assert "BUCKET_REPORT" in line, (
            f"{template_path}: environment-variables[0] must stay BUCKET_REPORT "
            "-- the EventBridge InputTransformer reads it positionally."
        )

    @pytest.mark.parametrize("template_path", _TEMPLATES)
    def test_alias_env_var_appended_after_legacy_ones(self, template_path):
        with open(template_path) as handle:
            text = handle.read()
        finserv_pos = text.index("- Name: ENABLE_FINSERV")
        alias_pos = text.index("- Name: ENABLE_RESPONSIBLE_AI_GOV")
        assert alias_pos > finserv_pos
