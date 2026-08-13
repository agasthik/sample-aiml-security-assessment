"""Compatibility locks for the persisted FinServ machine contracts.

These tests exist to fail loudly if the Responsible AI GRC rebrand — or any
later change — alters a value that crosses a process boundary or persists in a
customer artifact. Renaming a *label* is in scope for the rebrand; changing any
identifier asserted here is not.

Each assertion corresponds to a row in the "Public, persisted, and
compatibility contracts" section of the rebrand plan. Do not relax one of these
tests to make a rename pass — the rename is what is wrong in that case.
"""

from __future__ import annotations

import csv
import re
from io import StringIO

import pytest

from .support import finserv_app, finserv_schema

# ---------------------------------------------------------------------------
# CSV schema — 9 columns, exact order. Archived reports and the OWASP reader
# both parse positionally-stable output.
# ---------------------------------------------------------------------------

EXPECTED_CSV_COLUMNS = [
    "Check_ID",
    "Finding",
    "Finding_Details",
    "Resolution",
    "Reference",
    "Severity",
    "Status",
    "Region",
    "Compliance_Frameworks",
]


def _sample_finding(**overrides) -> dict:
    payload = dict(
        check_id="FS-01",
        finding_name="Example Finding",
        finding_details="Example details.",
        resolution="Example resolution.",
        reference="https://example.com/doc",
        severity="Medium",
        status="Failed",
        region="us-east-1",
        compliance_frameworks="FFIEC CAT | SR 11-7",
    )
    payload.update(overrides)
    return finserv_schema.create_finding(**payload)


def _as_check_result(*findings: dict) -> dict:
    """Wrap findings in the check-result envelope generate_csv_report consumes."""
    return {
        "check_name": "Contract Lock",
        "status": "PASS",
        "details": "",
        "csv_data": list(findings),
    }


def test_csv_header_is_the_nine_column_contract():
    csv_text = finserv_app.generate_csv_report([_as_check_result(_sample_finding())])
    header = next(csv.reader(StringIO(csv_text)))
    assert header == EXPECTED_CSV_COLUMNS


def test_csv_report_round_trips_every_column():
    finding = _sample_finding()
    csv_text = finserv_app.generate_csv_report([_as_check_result(finding)])
    row = next(csv.DictReader(StringIO(csv_text)))
    for column in EXPECTED_CSV_COLUMNS:
        expected = finding[column]
        # Severity and Status are str-subclassed enums; the CSV must carry the
        # bare value ("Medium"), never the Enum repr ("SeverityEnum.MEDIUM").
        assert row[column] == getattr(expected, "value", expected)


def test_csv_emits_enum_values_not_enum_reprs():
    csv_text = finserv_app.generate_csv_report(
        [_as_check_result(_sample_finding(severity="High", status="Passed"))]
    )
    row = next(csv.DictReader(StringIO(csv_text)))
    assert row["Severity"] == "High"
    assert row["Status"] == "Passed"
    assert "SeverityEnum" not in csv_text
    assert "StatusEnum" not in csv_text


# ---------------------------------------------------------------------------
# Value domains — Status and Severity are closed sets. Downstream report code
# and the OWASP mapper both branch on these exact strings.
# ---------------------------------------------------------------------------


def test_status_enum_value_domain_is_frozen():
    assert {member.value for member in finserv_schema.StatusEnum} == {
        "Failed",
        "Passed",
        "N/A",
    }


def test_severity_enum_value_domain_is_frozen():
    assert {member.value for member in finserv_schema.SeverityEnum} == {
        "High",
        "Medium",
        "Low",
        "Informational",
    }


# ---------------------------------------------------------------------------
# Check ID namespace — FS-00 plus FS-01..FS-69. Renumbering breaks the 42 OWASP
# mappings, the severity register, and historical comparison.
# ---------------------------------------------------------------------------

CHECK_ID_PATTERN = r"^[A-Z]{2,3}-\d{2}$"


def test_check_id_pattern_is_frozen():
    assert re.match(CHECK_ID_PATTERN, "FS-00")
    assert re.match(CHECK_ID_PATTERN, "FS-69")
    assert re.match(CHECK_ID_PATTERN, "BR-14")


@pytest.mark.parametrize("check_id", ["FS-00", "FS-01", "FS-27", "FS-69"])
def test_schema_accepts_the_finserv_namespace(check_id):
    assert _sample_finding(check_id=check_id)["Check_ID"] == check_id


@pytest.mark.parametrize("check_id", ["FS-1", "fs-01", "FSRV-01", "FS-100", "FS01"])
def test_schema_rejects_ids_outside_the_namespace(check_id):
    with pytest.raises(ValueError):
        _sample_finding(check_id=check_id)


def _registry_check_ids() -> list[str]:
    checks = finserv_app.build_finserv_checks(
        {"role_permissions": {}, "user_permissions": {}}
    )
    return [check_id for check_id, _callable in checks]


def test_registry_check_ids_are_stable():
    """64 unique IDs across 65 entries: FS-27 is intentionally duplicated."""
    check_ids = _registry_check_ids()
    assert len(check_ids) == 65
    assert len(set(check_ids)) == 64
    assert check_ids.count("FS-27") == 2


def test_merged_extension_ids_stay_out_of_the_registry():
    """FS-17/18/19/23/64 are merged into upstream Bedrock/SageMaker checks."""
    check_ids = set(_registry_check_ids())
    for merged in ("FS-17", "FS-18", "FS-19", "FS-23", "FS-64"):
        assert merged not in check_ids


def test_compliance_map_covers_exactly_the_registry_ids():
    """COMPLIANCE_MAP must not grow orphans or develop gaps."""
    assert len(finserv_app.COMPLIANCE_MAP) == 64
    for check_id in finserv_app.COMPLIANCE_MAP:
        assert re.match(CHECK_ID_PATTERN, check_id)
        assert check_id.startswith("FS-")


# ---------------------------------------------------------------------------
# FS-00 — emitted, CSV-persisted, schema-valid, and NOT in the check registry,
# so registry-based audits miss it. Locked here explicitly.
# ---------------------------------------------------------------------------


def test_fs_00_is_emitted_and_schema_valid():
    row = finserv_app._no_regional_genai_resources_row("eu-west-1")
    assert row["Check_ID"] == "FS-00"
    assert row["Status"] == "N/A"
    assert row["Severity"] == "Informational"
    assert row["Region"] == "eu-west-1"
    assert "eu-west-1" in row["Finding_Details"]


def test_fs_00_survives_csv_serialization():
    csv_text = finserv_app.generate_csv_report(
        [_as_check_result(finserv_app._no_regional_genai_resources_row("ap-south-1"))]
    )
    row = next(csv.DictReader(StringIO(csv_text)))
    assert row["Check_ID"] == "FS-00"
    assert row["Region"] == "ap-south-1"


def test_fs_00_is_not_in_the_check_registry():
    """Guards the assumption that makes FS-00 easy to miss."""
    assert "FS-00" not in set(_registry_check_ids())
    assert "FS-00" not in finserv_app.COMPLIANCE_MAP


# ---------------------------------------------------------------------------
# Reserved finding-name prefixes — report code and the severity register both
# key off these exact strings.
# ---------------------------------------------------------------------------


def test_could_not_assess_prefix_is_frozen():
    assert finserv_app.COULD_NOT_ASSESS_PREFIX == "COULD NOT ASSESS: "


def test_advisory_prefix_is_still_in_use():
    advisory_names = [
        name for name in finserv_app.SEVERITY_REGISTER if name.startswith("ADVISORY: ")
    ]
    assert advisory_names, "the ADVISORY: prefix is a report-facing contract"


# ---------------------------------------------------------------------------
# S3 object name — archived reports and the OWASP reader depend on this prefix.
# ---------------------------------------------------------------------------


def test_csv_object_name_keeps_the_legacy_prefix():
    captured_keys = []

    class _StubS3:
        def put_object(self, **kwargs):
            captured_keys.append(kwargs["Key"])
            return {}

    original = finserv_app.boto3.client
    finserv_app.boto3.client = lambda *a, **k: _StubS3()
    try:
        url = finserv_app.write_to_s3("20260807_120000", "Check_ID\n", "bucket-name")
    finally:
        finserv_app.boto3.client = original

    # Phase 2 Stage 2b (see docs/RESPONSIBLE_AI_GRC_PHASE2_STAGE2B_DESIGN.md,
    # item 5): write_to_s3 now writes TWO objects, the legacy one plus an
    # additive Responsible AI GRC alias. The legacy key remains the returned
    # url and the durable contract archived reports and the OWASP reader key
    # off; the alias is additional, not a replacement.
    assert "finserv_security_report_20260807_120000.csv" in captured_keys
    assert "responsible_ai_gov_security_report_20260807_120000.csv" in captured_keys
    assert len(captured_keys) == 2
    assert url.endswith("finserv_security_report_20260807_120000.csv")
