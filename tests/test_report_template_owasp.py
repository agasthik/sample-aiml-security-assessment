"""Test that report_template.generate_html_report renders the OWASP
compliance-standard section when the "owasp" service key has findings.
"""

import importlib.util
import json
import os
import sys

_report_dir = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment/functions/security/generate_consolidated_report",
    )
)
if _report_dir not in sys.path:
    sys.path.insert(0, _report_dir)

_spec = importlib.util.spec_from_file_location(
    "report_template_mod", os.path.join(_report_dir, "report_template.py")
)
report_template = importlib.util.module_from_spec(_spec)
sys.modules["report_template_mod"] = report_template
_spec.loader.exec_module(report_template)


def _data(html):
    return report_template.extract_report_data(html)


def _overview(html, label):
    return next(m for m in _data(html)["overview"] if m["label"] == label)


def _base_kwargs():
    """Minimum valid inputs for generate_html_report."""
    return {
        "all_findings": [],
        "service_findings": {
            "bedrock": [],
            "sagemaker": [],
            "agentcore": [],
            "agentic": [],
            "responsible-ai-grc": [],
            "owasp": [],
        },
        "service_stats": {
            "bedrock": {"passed": 0, "failed": 0, "na": 0},
            "sagemaker": {"passed": 0, "failed": 0, "na": 0},
            "agentcore": {"passed": 0, "failed": 0, "na": 0},
            "agentic": {"passed": 0, "failed": 0, "na": 0},
            "responsible-ai-grc": {"passed": 0, "failed": 0, "na": 0},
            "owasp": {"passed": 0, "failed": 0, "na": 0},
        },
        "mode": "single",
        "account_id": "111122223333",
        "timestamp": "January 1, 2026 00:00:00 UTC",
        "regions": ["us-east-1"],
    }


def _owasp_finding(check_id, status="Passed"):
    return {
        "Check_ID": check_id,
        "Finding": f"{check_id} test",
        "Finding_Details": "d",
        "Resolution": "r",
        "Reference": "https://genai.owasp.org/llm-top-10/",
        "Severity": "Medium",
        "Status": status,
        "Region": "us-east-1",
        "_service": "owasp",
    }


def _direct_finding(check_id, status, severity, details):
    service = "agentcore" if check_id.startswith("AC-") else "bedrock"
    return {
        "Check_ID": check_id,
        "Finding": f"{check_id} test",
        "Finding_Details": details,
        "Resolution": "r",
        "Reference": "https://docs.aws.amazon.com/bedrock/",
        "Severity": severity,
        "Status": status,
        "Region": "us-east-1",
        "_service": service,
    }


class TestOWASPSectionRendering:
    def test_no_owasp_findings_hides_compliance_section(self):
        html = report_template.generate_html_report(**_base_kwargs())
        data = _data(html)
        # When there are zero OWASP findings, no compliance nav / filter option.
        assert "By Compliance Standard" not in [g["heading"] for g in data["navGroups"]]
        assert "owasp" not in [o["value"] for o in data["filters"]["areas"]]
        assert "owasp" not in [a["slug"] for a in data["areas"]]

    def test_with_owasp_findings_renders_all_owasp_ui(self):
        kwargs = _base_kwargs()
        f1 = _owasp_finding("OW-01", status="Failed")
        f2 = _owasp_finding("OW-06", status="Passed")
        kwargs["all_findings"] = [f1, f2]
        kwargs["service_findings"]["owasp"] = [f1, f2]
        kwargs["service_stats"]["owasp"] = {"passed": 1, "failed": 1, "na": 0}

        html = report_template.generate_html_report(**kwargs)

        data = _data(html)
        # Navigation
        nav = {g["heading"]: g["areas"] for g in data["navGroups"]}
        assert nav["By Compliance Standard"] == ["owasp"]
        owasp = next(a for a in data["areas"] if a["slug"] == "owasp")
        assert owasp["name"] == "OWASP Top 10 LLM"
        assert owasp["countText"] == "2"
        # Filter option
        assert {"value": "owasp", "label": "OWASP Top 10 LLM"} in data["filters"][
            "areas"
        ]
        # Section — heading uses the registry's `section_title`, which
        # for OWASP is "OWASP Top 10 for LLM Findings" (with "for").
        assert owasp["sectionTitle"] == "OWASP Top 10 for LLM Findings"
        assert "OWASP Top 10 LLM" in [
            c["label"] for g in data["methodology"]["scopeGroups"] for c in g["chips"]
        ]

    def test_contextual_rows_do_not_inflate_open_action_items(self):
        kwargs = _base_kwargs()
        bedrock_finding = {
            "Check_ID": "BR-01",
            "Finding": "Bedrock test",
            "Finding_Details": "d",
            "Resolution": "r",
            "Reference": "https://docs.aws.amazon.com/bedrock/",
            "Severity": "High",
            "Status": "Failed",
            "Region": "us-east-1",
            "_service": "bedrock",
        }
        owasp_finding = _owasp_finding("OW-01", status="Failed")
        kwargs["all_findings"] = [bedrock_finding, owasp_finding]
        kwargs["service_findings"]["bedrock"] = [bedrock_finding]
        kwargs["service_findings"]["owasp"] = [owasp_finding]
        kwargs["service_stats"]["bedrock"] = {"passed": 0, "failed": 1, "na": 0}
        kwargs["service_stats"]["owasp"] = {"passed": 0, "failed": 1, "na": 0}

        html = report_template.generate_html_report(**kwargs)

        open_items = _overview(html, "Open Action Items")
        assert (open_items["value"], open_items["description"]) == (
            "1",
            "Direct failed service rows",
        )
        lens = _overview(html, "Lens / Compliance Rows")
        assert (lens["value"], lens["description"]) == (
            "1",
            "1 failed; may map to service rows",
        )
        overall = _data(html)["risk"]["overall"]
        assert overall["passRateText"] == "0.0%"
        assert overall["description"] == "0 of 1 scored controls passed"

    def test_repeated_resource_passes_count_as_one_scored_control(self):
        kwargs = _base_kwargs()
        failed_control = _direct_finding(
            "BR-01", "Failed", "High", "One unrelated control failed."
        )
        record_passes = [
            _direct_finding(
                "AR-08",
                "Passed",
                "Medium",
                f"Registry record {record_index} has valid provenance.",
            )
            for record_index in range(100)
        ]
        kwargs["all_findings"] = [failed_control, *record_passes]
        kwargs["service_findings"]["bedrock"] = [failed_control]
        kwargs["service_findings"]["agentcore"] = record_passes
        kwargs["service_stats"]["bedrock"] = {"passed": 0, "failed": 1, "na": 0}
        kwargs["service_stats"]["agentcore"] = {
            "passed": len(record_passes),
            "failed": 0,
            "na": 0,
        }

        html = report_template.generate_html_report(**kwargs)

        overall = _data(html)["risk"]["overall"]
        assert overall["passRateText"] == "50.0%"
        assert overall["description"] == "1 of 2 scored controls passed"
        assert "99.5%" not in html

    def test_any_failed_resource_makes_the_unique_control_fail(self):
        findings = [
            _direct_finding(
                "AR-08",
                "Passed",
                "Medium",
                f"Registry record {record_index} has valid provenance.",
            )
            for record_index in range(10)
        ]
        findings.append(
            _direct_finding(
                "AR-08",
                "Failed",
                "Medium",
                "One registry record lacks valid provenance.",
            )
        )

        controls = report_template._aggregate_scored_controls(
            findings,
            {"agentic", "responsible-ai-grc", "owasp"},
        )

        assert controls == [
            {"check_id": "AR-08", "status": "failed", "severity": "medium"}
        ]

    def test_na_only_control_is_excluded_from_the_score(self):
        findings = [
            _direct_finding(
                "AR-07",
                "N/A",
                "Informational",
                "Registry record lifecycle state is advisory.",
            )
        ]

        controls = report_template._aggregate_scored_controls(
            findings,
            {"agentic", "responsible-ai-grc", "owasp"},
        )

        assert controls == []

    def test_finding_fields_are_escaped_and_reference_scheme_is_validated(self):
        kwargs = _base_kwargs()
        finding = {
            "Check_ID": 'OW-01"><script>alert(1)</script>',
            "Finding": '<img src=x onerror="alert(1)">',
            "Finding_Details": '<script>alert("details")</script>',
            "Resolution": 'Use "quotes" and <b>markup</b> safely.',
            "Reference": "javascript:alert(1)",
            "Severity": "High",
            "Status": "Failed",
            "Region": 'us-east-1" onclick="alert(1)',
            "_service": "owasp",
        }
        kwargs["all_findings"] = [finding]
        kwargs["service_findings"]["owasp"] = [finding]
        kwargs["service_stats"]["owasp"] = {"passed": 0, "failed": 1, "na": 0}

        html = report_template.generate_html_report(**kwargs)

        # The JSON model escapes "<" so no finding text can start markup or
        # close its <script> element; the UI renders the text, never markup.
        assert "<script>alert" not in html
        assert "<img src=x" not in html
        assert "<b>markup</b>" not in html
        assert "\\u003cscript\\u003ealert" in html
        (row,) = _data(html)["findings"]
        # Text is preserved exactly; only the transport is escaped.
        assert row["checkId"] == 'OW-01"><script>alert(1)</script>'
        assert row["finding"] == '<img src=x onerror="alert(1)">'
        assert row["details"] == '<script>alert("details")</script>'
        assert row["resolution"] == 'Use "quotes" and <b>markup</b> safely.'
        assert row["region"] == 'us-east-1" onclick="alert(1)'
        # A non-HTTPS reference is not offered as a link, nor kept anywhere.
        assert row["reference"] is None
        assert "javascript:alert(1)" not in json.dumps(_data(html))

    def test_compliance_standards_is_data_driven(self):
        """The extensibility contract: adding a standard is a data-only edit."""
        assert isinstance(report_template.COMPLIANCE_STANDARDS, list)
        slugs = [s["slug"] for s in report_template.COMPLIANCE_STANDARDS]
        assert "owasp" in slugs
        # Every entry must expose the keys the loop reads.
        for s in report_template.COMPLIANCE_STANDARDS:
            for required in (
                "slug",
                "name",
                "prefix",
                "icon",
                "reference_url",
                "section_title",
                "scope_text",
            ):
                assert required in s, f"Missing '{required}' in {s.get('slug')}"

    def test_priority_alert_label_uses_compliance_registry(self, monkeypatch):
        """Future compliance standards should not fall through as AgentCore."""
        monkeypatch.setattr(
            report_template,
            "COMPLIANCE_STANDARDS",
            report_template.COMPLIANCE_STANDARDS
            + [
                {
                    "slug": "nist",
                    "name": "NIST AI RMF",
                    "prefix": "NR-",
                    "icon": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8"/>',
                    "reference_url": "https://example.com/nist",
                    "section_title": "NIST AI RMF Findings",
                    "scope_text": "Test scope.",
                }
            ],
        )
        kwargs = _base_kwargs()
        finding = {
            "Check_ID": "NR-01",
            "Finding": "NIST AI RMF test finding",
            "Finding_Details": "d",
            "Resolution": "r",
            "Reference": "https://example.com/nist",
            "Severity": "High",
            "Status": "Failed",
            "Region": "us-east-1",
            "_service": "nist",
        }
        kwargs["all_findings"] = [finding]
        kwargs["service_findings"]["nist"] = [finding]
        kwargs["service_stats"]["nist"] = {"passed": 0, "failed": 1, "na": 0}

        html = report_template.generate_html_report(**kwargs)

        assert [a["area"] for a in _data(html)["alerts"]] == ["NIST AI RMF"]


def test_grc_only_report_has_no_direct_service_score():
    kwargs = _base_kwargs()
    row = {
        **_direct_finding("BR-01", "Failed", "High", "Synthetic governance finding"),
        "Check_ID": "FS-01",
        "_service": "responsible-ai-grc",
    }
    kwargs["all_findings"] = [row]
    kwargs["service_findings"]["responsible-ai-grc"] = [row]
    kwargs["service_stats"]["responsible-ai-grc"]["failed"] = 1
    kwargs["service_selection"] = dict.fromkeys(
        ("bedrock", "sagemaker", "agentcore", "agent-registry"), False
    )
    data = _data(report_template.generate_html_report(**kwargs))
    risk = data["risk"]
    descriptions = [r["description"] for r in [*risk["severity"], risk["overall"]]]
    assert risk["overall"]["description"] == "0 of 0 scored controls passed"
    assert "0 of 1 scored controls passed" not in descriptions
    assert "responsible-ai-grc" in [a["slug"] for a in data["areas"]]
    assert [f["checkId"] for f in data["findings"]] == ["FS-01"]
