"""Phase 2 Stage 2b, item 5 — fs_exclude_args covers both CSV prefixes.

Executes the actual `fs_exclude_args` shell snippet from buildspec.yml
(extracted verbatim, not reimplemented) to confirm that when FinServ /
Responsible AI GRC is disabled, BOTH the legacy `finserv_security_report_*`
and the additive `responsible_ai_gov_security_report_*` CSVs are excluded from
every `aws s3 cp`/`sync` into the customer-facing report bucket -- and that
neither is excluded when the capability is enabled.

See docs/RESPONSIBLE_AI_GRC_PHASE2_STAGE2B_DESIGN.md for the full design.
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


def _run_fs_exclude_resolution(enable_finserv):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    if enable_finserv is not None:
        env["ENABLE_FINSERV"] = enable_finserv
    script = _FS_EXCLUDE_SCRIPT + '\nprintf "%s\\n" "${fs_exclude_args[@]}"\n'
    result = subprocess.run(
        ["bash", "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.returncode, [line for line in result.stdout.splitlines() if line]


class TestFsExcludeArgsCoversBothPrefixes:
    def test_disabled_excludes_both_legacy_and_alias_prefixes(self):
        code, output_lines = _run_fs_exclude_resolution(enable_finserv="false")
        assert code == 0
        assert "--exclude" in output_lines
        assert "finserv_security_report_*.csv" in output_lines
        assert "responsible_ai_gov_security_report_*.csv" in output_lines

    def test_disabled_by_absence_excludes_both_prefixes(self):
        # ENABLE_FINSERV genuinely unset -- the shell default ${ENABLE_FINSERV:-false}
        # must behave identically to an explicit "false".
        code, output_lines = _run_fs_exclude_resolution(enable_finserv=None)
        assert code == 0
        assert "finserv_security_report_*.csv" in output_lines
        assert "responsible_ai_gov_security_report_*.csv" in output_lines

    def test_enabled_excludes_neither_prefix(self):
        code, output_lines = _run_fs_exclude_resolution(enable_finserv="true")
        assert code == 0
        assert output_lines == [], (
            f"expected an empty fs_exclude_args array when enabled, got {output_lines}"
        )

    def test_both_exclude_flags_are_paired_with_exclude_option(self):
        """Confirms the array is well-formed for its actual use site: each
        CSV glob must be preceded by its own --exclude flag (a bash array
        expanded as "${fs_exclude_args[@]}" into an aws cli command), not a
        single --exclude followed by two globs (which aws cli would not
        interpret as two separate exclusions)."""
        _, output_lines = _run_fs_exclude_resolution(enable_finserv="false")
        assert output_lines == [
            "--exclude",
            "finserv_security_report_*.csv",
            "--exclude",
            "responsible_ai_gov_security_report_*.csv",
        ]
