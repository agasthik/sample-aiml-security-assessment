"""Tests for scripts/convert_finserv_csv_prefix.py.

This converter is written ahead of need for Phase 2 Stage 2b (see
docs/RESPONSIBLE_AI_GRC_PHASE2_STAGE2B_DESIGN.md) and does not run against any
real second CSV prefix today. These tests exercise its diff logic directly
against realistic fixture CSVs matching the actual 9-column schema written by
generate_csv_report() in finserv_assessments/app.py, so the tool is proven
correct before the day it is actually needed.
"""

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT_PATH = os.path.join(REPO_ROOT, "scripts", "convert_finserv_csv_prefix.py")

_spec = importlib.util.spec_from_file_location(
    "convert_finserv_csv_prefix", SCRIPT_PATH
)
convert_finserv_csv_prefix = importlib.util.module_from_spec(_spec)
# Register in sys.modules BEFORE exec_module: the target script uses
# `from __future__ import annotations` with dataclasses, and dataclasses
# resolves annotations by looking up the defining module in sys.modules by
# name. Without this, exec_module raises AttributeError on the dataclass
# decorators because the module isn't registered under its own __module__ yet.
sys.modules["convert_finserv_csv_prefix"] = convert_finserv_csv_prefix
_spec.loader.exec_module(convert_finserv_csv_prefix)

diff_reports = convert_finserv_csv_prefix.diff_reports
main = convert_finserv_csv_prefix.main

CSV_HEADER = "Check_ID,Finding,Finding_Details,Resolution,Reference,Severity,Status,Region,Compliance_Frameworks\n"


def _row(
    check_id="FS-01",
    finding="AWS Shield Advanced Not Enabled",
    details="No subscription found.",
    resolution="Enable AWS Shield Advanced.",
    reference="FS-01",
    severity="High",
    status="Failed",
    region="us-east-1",
    frameworks="SR 11-7|FFIEC CAT",
):
    return f'"{check_id}","{finding}","{details}","{resolution}","{reference}","{severity}","{status}","{region}","{frameworks}"\n'


class TestDiffReports:
    def test_identical_csvs_are_clean(self):
        csv_text = CSV_HEADER + _row()
        result = diff_reports(csv_text, csv_text)
        assert result.is_clean()
        assert result.legacy_count == 1
        assert result.new_count == 1

    def test_legacy_only_row_is_reported(self):
        legacy = CSV_HEADER + _row() + _row(check_id="FS-02", finding="Something Else")
        new = CSV_HEADER + _row()
        result = diff_reports(legacy, new)
        assert not result.is_clean()
        assert len(result.legacy_only) == 1
        assert result.legacy_only[0][0] == "FS-02"
        assert not result.new_only
        assert not result.differing

    def test_new_only_row_is_reported(self):
        legacy = CSV_HEADER + _row()
        new = CSV_HEADER + _row() + _row(check_id="FS-03", finding="New Check")
        result = diff_reports(legacy, new)
        assert not result.is_clean()
        assert not result.legacy_only
        assert len(result.new_only) == 1
        assert result.new_only[0][0] == "FS-03"

    def test_differing_compliance_frameworks_is_reported(self):
        # This is the ONE intentional, declared break per rebrand-plan.md
        # section 7 -- Compliance_Frameworks values are allowed to differ
        # across a mapping-reconciliation boundary. The converter must still
        # surface it (so a human can confirm it's the expected declared
        # break), just not treat it as a structural mismatch.
        legacy = CSV_HEADER + _row(frameworks="SR 11-7|FFIEC CAT")
        new = CSV_HEADER + _row(frameworks="SR 11-7|FFIEC CAT|GDPR")
        result = diff_reports(legacy, new)
        assert not result.is_clean()
        assert not result.legacy_only
        assert not result.new_only
        assert len(result.differing) == 1
        key = next(iter(result.differing))
        legacy_values, new_values = result.differing[key]
        assert legacy_values["Compliance_Frameworks"] == "SR 11-7|FFIEC CAT"
        assert new_values["Compliance_Frameworks"] == "SR 11-7|FFIEC CAT|GDPR"

    def test_differing_status_is_reported(self):
        legacy = CSV_HEADER + _row(status="Failed")
        new = CSV_HEADER + _row(status="Passed")
        result = diff_reports(legacy, new)
        assert len(result.differing) == 1

    def test_legacy_only_mode_reports_all_rows_as_legacy_only(self):
        legacy = CSV_HEADER + _row() + _row(check_id="FS-02", finding="Other")
        result = diff_reports(legacy, None)
        assert result.legacy_count == 2
        assert result.new_count == 0
        assert len(result.legacy_only) == 2
        assert not result.new_only
        assert not result.differing

    def test_duplicate_identity_within_one_csv_raises(self):
        # Two rows with the same (Check_ID, Region, Finding) in a single CSV
        # indicates the SOURCE csv has a duplicate finding -- a real bug this
        # tool should surface loudly, not silently collapse.
        legacy = CSV_HEADER + _row() + _row()
        with pytest.raises(ValueError, match="Duplicate identity"):
            diff_reports(legacy, None)

    def test_missing_expected_column_raises(self):
        bad_csv = "Check_ID,Finding\nFS-01,Something\n"
        with pytest.raises(ValueError, match="missing expected column"):
            diff_reports(bad_csv, None)

    def test_multiple_rows_with_distinct_check_ids(self):
        legacy = (
            CSV_HEADER
            + _row(check_id="FS-01", finding="A")
            + _row(check_id="FS-02", finding="B")
            + _row(check_id="FS-03", finding="C")
        )
        result = diff_reports(legacy, legacy)
        assert result.is_clean()
        assert result.legacy_count == 3


class TestCliLocalMode:
    def test_local_legacy_only(self, tmp_path):
        legacy_path = tmp_path / "legacy.csv"
        legacy_path.write_text(CSV_HEADER + _row())
        exit_code = main(["--local-legacy", str(legacy_path)])
        assert exit_code == 0

    def test_local_legacy_and_new_clean(self, tmp_path):
        legacy_path = tmp_path / "legacy.csv"
        new_path = tmp_path / "new.csv"
        content = CSV_HEADER + _row()
        legacy_path.write_text(content)
        new_path.write_text(content)
        exit_code = main(
            ["--local-legacy", str(legacy_path), "--local-new", str(new_path)]
        )
        assert exit_code == 0

    def test_local_legacy_and_new_with_diff_returns_nonzero(self, tmp_path):
        legacy_path = tmp_path / "legacy.csv"
        new_path = tmp_path / "new.csv"
        legacy_path.write_text(CSV_HEADER + _row(check_id="FS-01"))
        new_path.write_text(CSV_HEADER + _row(check_id="FS-02"))
        exit_code = main(
            ["--local-legacy", str(legacy_path), "--local-new", str(new_path)]
        )
        assert exit_code == 2

    def test_missing_local_legacy_errors(self):
        with pytest.raises(SystemExit):
            main(["--local-new", "somewhere.csv"])

    def test_mixing_local_and_s3_args_errors(self, tmp_path):
        legacy_path = tmp_path / "legacy.csv"
        legacy_path.write_text(CSV_HEADER + _row())
        with pytest.raises(SystemExit):
            main(["--local-legacy", str(legacy_path), "--bucket", "some-bucket"])

    def test_no_args_errors(self):
        with pytest.raises(SystemExit):
            main([])
