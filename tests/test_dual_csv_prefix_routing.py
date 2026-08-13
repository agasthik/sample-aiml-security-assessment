"""Phase 2 Stage 2b, item 5: additive dual CSV prefix routing and dedup.

finserv_assessments/app.py's write_to_s3() now dual-writes byte-identical
content under both `finserv_security_report_<execution_id>.csv` (legacy) and
`responsible_ai_gov_security_report_<execution_id>.csv` (additive alias). This
file verifies that generate_consolidated_report/app.py's get_assessment_results
routes both into the SAME "finserv" report category rather than creating a
second, always-duplicate category, and that the downstream generate_html_report
dedup collapses identical rows from both sources into one logical finding.

See docs/RESPONSIBLE_AI_GRC_PHASE2_STAGE2B_DESIGN.md for the full design.
"""

import importlib.util
import os
import sys
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_report_dir = os.path.join(
    REPO_ROOT,
    "aiml-security-assessment",
    "functions",
    "security",
    "generate_consolidated_report",
)
if _report_dir not in sys.path:
    sys.path.insert(0, _report_dir)

_spec = importlib.util.spec_from_file_location(
    "dual_prefix_report_app", os.path.join(_report_dir, "app.py")
)
report_app = importlib.util.module_from_spec(_spec)
sys.modules["dual_prefix_report_app"] = report_app
_spec.loader.exec_module(report_app)


def _csv_bytes(
    rows,
    header="Check_ID,Finding,Finding_Details,Resolution,Reference,Severity,Status,Region,Compliance_Frameworks",
):
    lines = [header]
    for r in rows:
        lines.append(
            ",".join(
                [
                    r.get("Check_ID", ""),
                    r.get("Finding", ""),
                    r.get("Finding_Details", ""),
                    r.get("Resolution", ""),
                    r.get("Reference", ""),
                    r.get("Severity", ""),
                    r.get("Status", ""),
                    r.get("Region", ""),
                    r.get("Compliance_Frameworks", ""),
                ]
            )
        )
    return "\n".join(lines).encode("utf-8")


def _fake_s3(objects_by_key):
    """objects_by_key: {s3_key: bytes_content}. Simulates list_objects_v2
    (via a paginator) returning one page per prefix, plus get_object."""
    client = MagicMock()

    class _FakePaginator:
        def paginate(self, Bucket, Prefix):
            matching = [
                {"Key": key} for key in objects_by_key if key.startswith(Prefix)
            ]
            yield {"Contents": matching}

    client.get_paginator.return_value = _FakePaginator()

    def get_object(Bucket, Key):
        return {"Body": MagicMock(read=MagicMock(return_value=objects_by_key[Key]))}

    client.get_object.side_effect = get_object
    return client


class TestDualPrefixRouting:
    def test_alias_only_object_routes_into_finserv_category(self):
        """If only the additive alias object exists (legacy missing -- an
        edge case, but the router must not silently drop it into 'unknown'),
        its rows land in the SAME 'finserv' category, not a new one."""
        execution_id = "exec-abc"
        row = {
            "Check_ID": "FS-01",
            "Finding": "Alias-Only Finding",
            "Finding_Details": "d",
            "Resolution": "r",
            "Reference": "https://example.com",
            "Severity": "High",
            "Status": "Failed",
            "Region": "us-east-1",
            "Compliance_Frameworks": "",
        }
        key = f"responsible_ai_gov_security_report_{execution_id}.csv"
        client = _fake_s3({key: _csv_bytes([row])})

        with (
            patch.object(report_app.boto3, "client", return_value=client),
            patch.dict(os.environ, {"AIML_ASSESSMENT_BUCKET_NAME": "test-bucket"}),
        ):
            results = report_app.get_assessment_results(execution_id)

        assert "finserv" in results
        assert key.replace(".csv", "").lower() in results["finserv"]
        assert (
            results["finserv"][key.replace(".csv", "").lower()][0]["Check_ID"]
            == "FS-01"
        )
        # Confirm no stray category was created for the alias prefix.
        assert "responsible_ai_gov" not in results

    def test_both_legacy_and_alias_objects_route_into_finserv_category(self):
        execution_id = "exec-abc"
        row = {
            "Check_ID": "FS-02",
            "Finding": "Both Files Finding",
            "Finding_Details": "d",
            "Resolution": "r",
            "Reference": "https://example.com",
            "Severity": "High",
            "Status": "Failed",
            "Region": "us-east-1",
            "Compliance_Frameworks": "",
        }
        legacy_key = f"finserv_security_report_{execution_id}.csv"
        alias_key = f"responsible_ai_gov_security_report_{execution_id}.csv"
        client = _fake_s3({legacy_key: _csv_bytes([row]), alias_key: _csv_bytes([row])})

        with (
            patch.object(report_app.boto3, "client", return_value=client),
            patch.dict(os.environ, {"AIML_ASSESSMENT_BUCKET_NAME": "test-bucket"}),
        ):
            results = report_app.get_assessment_results(execution_id)

        finserv_assessment_types = list(results["finserv"].keys())
        assert legacy_key.replace(".csv", "").lower() in finserv_assessment_types
        assert alias_key.replace(".csv", "").lower() in finserv_assessment_types
        assert len(finserv_assessment_types) == 2

    def test_end_to_end_html_report_deduplicates_across_both_prefixes(self):
        """The realistic case end to end: both CSV objects contribute the
        SAME logical finding; generate_html_report's dedup (keyed on
        account/service/check_id/region/details) must collapse them to one
        row in the rendered report, matching the OWASP-layer dedup test.
        """
        execution_id = "exec-abc"
        row = {
            "Check_ID": "FS-03",
            "Finding": "Duplicate Across Both Files",
            "Finding_Details": "identical details",
            "Resolution": "r",
            "Reference": "https://example.com",
            "Severity": "High",
            "Status": "Failed",
            "Region": "us-east-1",
            "Compliance_Frameworks": "",
        }
        legacy_key = f"finserv_security_report_{execution_id}.csv"
        alias_key = f"responsible_ai_gov_security_report_{execution_id}.csv"
        client = _fake_s3({legacy_key: _csv_bytes([row]), alias_key: _csv_bytes([row])})

        with (
            patch.object(report_app.boto3, "client", return_value=client),
            patch.dict(os.environ, {"AIML_ASSESSMENT_BUCKET_NAME": "test-bucket"}),
        ):
            results = report_app.get_assessment_results(execution_id)

        html = report_app.generate_html_report(results, show_finserv=True)
        assert html.count("Duplicate Across Both Files") <= 2, (
            "each surviving logical finding may appear in both the nav/"
            "summary widgets and the table row, but must not be duplicated "
            "PER occurrence -- i.e. two source CSVs must not double the count"
        )
        # The summary metric (finserv_total) must read 1, not 2.
        assert 'metric-value">1<' in html
