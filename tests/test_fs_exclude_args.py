"""fs_exclude_args -- excludes the Responsible AI GRC CSV prefix when disabled.

Executes the actual `fs_exclude_args` shell snippet from buildspec.yml
(extracted verbatim, not reimplemented) to confirm that when Responsible AI
GRC is disabled, its `responsible_ai_grc_security_report_*` CSV is excluded
from every `aws s3 cp`/`sync` into the customer-facing report bucket -- and
that it is not excluded when the capability is enabled.

There is a single prefix and a single exclude flag now: the Phase 2 Stage 2b
additive alias prefix (`responsible_ai_gov_security_report_*`) has been
retired along with its dual-write, so there is nothing left to pair it with.
"""

import os
import subprocess

import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILDSPEC_PATH = os.path.join(REPO_ROOT, "buildspec.yml")


def _load_fs_exclude_args_script():
    """Extract the `fs_exclude_args=() ... fi` block verbatim from
    buildspec.yml's post_build phase.

    post_build's commands are not one-statement-per-list-entry the way
    build's are -- the relevant snippet lives inside one large multi-line
    `if [ $CODEBUILD_BUILD_SUCCEEDING -eq 0 ]; then ... fi` command string.
    Extract just the fs_exclude_args=() through its closing `fi` by line
    range within that block, rather than treating the whole block as the
    script (which would require a real CODEBUILD_BUILD_SUCCEEDING=1 and every
    downstream AWS CLI call this test has no business making).
    """
    with open(BUILDSPEC_PATH) as handle:
        data = yaml.safe_load(handle)
    commands = data["phases"]["post_build"]["commands"]

    for command in commands:
        if "fs_exclude_args=()" in command:
            lines = command.splitlines()
            start = next(
                i for i, line in enumerate(lines) if "fs_exclude_args=()" in line
            )
            # The block is exactly: fs_exclude_args=() / if [[ ... ]]; then / --exclude line(s) / fi
            end = next(
                i
                for i in range(start, len(lines))
                if lines[i].strip() == "fi" and i > start
            )
            return "\n".join(lines[start : end + 1])

    raise AssertionError(
        "Could not find the fs_exclude_args block in buildspec.yml -- has it "
        "moved or been reworded?"
    )


_FS_EXCLUDE_SCRIPT = _load_fs_exclude_args_script()


def _run_fs_exclude_resolution(enable_responsible_ai_grc):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    if enable_responsible_ai_grc is not None:
        env["ENABLE_RESPONSIBLE_AI_GRC"] = enable_responsible_ai_grc
    script = _FS_EXCLUDE_SCRIPT + '\nprintf "%s\\n" "${fs_exclude_args[@]}"\n'
    result = subprocess.run(
        ["bash", "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.returncode, [line for line in result.stdout.splitlines() if line]


class TestFsExcludeArgsCoversTheSinglePrefix:
    def test_disabled_excludes_the_responsible_ai_grc_prefix(self):
        code, output_lines = _run_fs_exclude_resolution(
            enable_responsible_ai_grc="false"
        )
        assert code == 0
        assert output_lines == [
            "--exclude",
            "responsible_ai_grc_security_report_*.csv",
        ]

    def test_disabled_by_absence_excludes_the_prefix(self):
        # ENABLE_RESPONSIBLE_AI_GRC genuinely unset -- the shell default
        # ${ENABLE_RESPONSIBLE_AI_GRC:-false} must behave identically to an
        # explicit "false".
        code, output_lines = _run_fs_exclude_resolution(enable_responsible_ai_grc=None)
        assert code == 0
        assert output_lines == [
            "--exclude",
            "responsible_ai_grc_security_report_*.csv",
        ]

    def test_enabled_excludes_nothing(self):
        code, output_lines = _run_fs_exclude_resolution(
            enable_responsible_ai_grc="true"
        )
        assert code == 0
        assert output_lines == [], (
            f"expected an empty fs_exclude_args array when enabled, got {output_lines}"
        )

    def test_exclude_flag_is_paired_with_exclude_option(self):
        """Confirms the array is well-formed for its actual use site: the
        CSV glob must be preceded by its own --exclude flag (a bash array
        expanded as "${fs_exclude_args[@]}" into an aws cli command)."""
        _, output_lines = _run_fs_exclude_resolution(enable_responsible_ai_grc="false")
        assert output_lines == [
            "--exclude",
            "responsible_ai_grc_security_report_*.csv",
        ]

    def test_legacy_prefixes_are_not_referenced(self):
        """The legacy finserv_security_report prefix and the retired
        responsible_ai_gov_security_report alias prefix must not appear in
        the buildspec snippet at all -- there is no dual-write to exclude."""
        assert "finserv_security_report" not in _FS_EXCLUDE_SCRIPT
        assert "responsible_ai_gov_security_report" not in _FS_EXCLUDE_SCRIPT
