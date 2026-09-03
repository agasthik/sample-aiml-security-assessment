"""Guard the dashboard widget arithmetic in report_template.generate_html_report.

The overview widgets (Unique Check IDs, Report Rows, Lens / Compliance Rows,
Overall pass rate, severity pass rates, and the per-region risk cards) are
derived, not stored, so a routing or severity change can silently shift them.
These tests pin the derivations that a new assessment area is most likely to
break, using AWS Agent Registry (`AR-*`) as the worked example:

* a control reported once per region collapses to one scored result,
* runtime markers and Informational rows never enter the scored denominator,
* account-scoped `Region == "Global"` rows get their own risk card without
  inflating the region count, and
* contextual lens/compliance rows stay out of the score.
"""

import importlib.util
import os
import re
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
    "report_template_widget_mod", os.path.join(_report_dir, "report_template.py")
)
report_template = importlib.util.module_from_spec(_spec)
sys.modules["report_template_widget_mod"] = report_template
_spec.loader.exec_module(report_template)


def _finding(check_id, severity, status, service, region="us-east-1"):
    return {
        "Check_ID": check_id,
        "Finding": f"{check_id} finding",
        "Finding_Details": "details",
        "Resolution": "Do the thing",
        "Reference": "https://docs.aws.amazon.com/",
        "Severity": severity,
        "Status": status,
        "Region": region,
        "_service": service,
        "Account_ID": "123456789012",
    }


def _render(service_findings, **kwargs):
    """Render a report from a {slug: [findings]} map, deriving service_stats."""
    stats = {}
    for slug, findings in service_findings.items():
        stats[slug] = {
            "passed": sum(1 for f in findings if f["Status"] == "Passed"),
            "failed": sum(1 for f in findings if f["Status"] == "Failed"),
            "na": sum(1 for f in findings if f["Status"] == "N/A"),
        }
    all_findings = [f for findings in service_findings.values() for f in findings]
    kwargs.setdefault("mode", "single")
    kwargs.setdefault("account_id", "123456789012")
    return report_template.generate_html_report(
        all_findings, service_findings, stats, **kwargs
    )


def _tile(html, label):
    """Return (value, sub-text) for the overview metric tile with this label."""
    match = re.search(
        r'<div class="metric-label">(?:(?!</div>).)*?'
        + re.escape(label)
        + r'</div><div class="metric-value">([^<]+)</div>'
        r'(?:<div class="metric-sub">([^<]*)</div>)?',
        html,
        re.S,
    )
    assert match, f"metric tile {label!r} not found"
    return match.group(1), match.group(2) or ""


def _severity_pass_rate(html, severity):
    match = re.search(
        r'<span class="severity '
        + severity
        + r'"[^>]*>'
        + severity.upper()
        + r"</span></div>"
        r'<div class="metric-value">([^<]+)</div>',
        html,
    )
    assert match, f"{severity} pass-rate tile not found"
    return match.group(1)


def _risk_card(html, label):
    """Return the text of the per-region / per-account risk card for `label`."""
    block = re.search(
        r'</h4>\s*<div class="metrics" style="margin-bottom: 32px;">(.*)', html, re.S
    )
    assert block, "risk card section not rendered"
    card = re.search(
        re.escape(label) + r'</div>(.*?)(?=<div class="metric[ "]|$)',
        block.group(1),
        re.S,
    )
    assert card, f"risk card {label!r} not found"
    return " ".join(re.sub(r"<[^>]+>", " ", card.group(1)).split())


def test_agent_registry_control_reported_per_region_scores_once():
    """A control failing in one region and passing in another fails overall.

    AR-01 is emitted per region, so the scored denominator must count the
    Check_ID once, and any failed assessable row must fail the control.
    """
    html = _render(
        {
            "bedrock": [_finding("BR-01", "High", "Passed", "bedrock")],
            "agent-registry": [
                _finding("AR-01", "High", "Failed", "agent-registry", "us-east-1"),
                _finding("AR-01", "High", "Passed", "agent-registry", "us-west-2"),
            ],
        },
        regions=["us-east-1", "us-west-2"],
    )

    # 3 rows, but only 2 scored controls: BR-01 and AR-01.
    assert _tile(html, "Report Rows")[0] == "3"
    assert _tile(html, "Unique Check IDs")[0] == "2"
    value, sub = _tile(html, "Overall")
    assert value == "50.0%"
    assert "1 of 2 scored controls passed" in sub
    # AR-01 failed once, so the High pass rate counts only BR-01 as passing.
    assert _severity_pass_rate(html, "high") == "50.0%"


def test_agent_registry_markers_and_advisory_rows_are_not_scored():
    """AR-00 and advisory AR rows stay out of the scored denominator.

    AR-00 is a runtime availability marker and AR-07 is advisory, so neither is
    a control that can pass or fail. Counting them would dilute the pass rate.
    """
    html = _render(
        {
            "agent-registry": [
                _finding("AR-00", "Informational", "N/A", "agent-registry"),
                _finding("AR-07", "Informational", "N/A", "agent-registry"),
                _finding("AR-05", "Medium", "Passed", "agent-registry"),
            ],
        }
    )

    assert _tile(html, "Report Rows")[0] == "3"
    value, sub = _tile(html, "Overall")
    assert value == "100.0%"
    assert "1 of 1 scored controls passed" in sub
    # The rows remain visible in the report even though they are unscored.
    assert "AR-00" in html
    assert "AR-07" in html


def test_informational_severity_never_enters_the_score_even_when_failed():
    """An Informational row is unscored regardless of its status.

    Advisory Agent Registry gaps are reported Informational on purpose. If the
    severity gate regressed, an advisory row carrying a Failed status would be
    counted as a failed control and depress the pass rate.
    """
    html = _render(
        {
            "agent-registry": [
                _finding("AR-03", "Medium", "Passed", "agent-registry"),
                _finding("AR-06", "Informational", "Failed", "agent-registry"),
            ],
        }
    )

    value, sub = _tile(html, "Overall")
    assert value == "100.0%"
    assert "1 of 1 scored controls passed" in sub


def test_na_status_never_enters_the_score_even_at_high_severity():
    """An N/A row is unscored regardless of its severity.

    Region-unavailable and access-denied paths resolve to N/A. If the status
    gate regressed, an unassessed control would be scored as though it had been
    checked.
    """
    html = _render(
        {
            "agent-registry": [
                _finding("AR-03", "Medium", "Passed", "agent-registry"),
                _finding("AR-01", "High", "N/A", "agent-registry"),
            ],
        }
    )

    value, sub = _tile(html, "Overall")
    assert value == "100.0%"
    assert "1 of 1 scored controls passed" in sub


def test_failed_control_reports_its_highest_severity_across_rows():
    """A control failing at two severities is scored at the highest one.

    AR-01 can fail Medium for one principal and High for another; the scored
    control must surface High so the priority ordering is not understated.
    """
    html = _render(
        {
            "agent-registry": [
                _finding("AR-01", "Medium", "Failed", "agent-registry", "us-east-1"),
                _finding("AR-01", "High", "Failed", "agent-registry", "us-west-2"),
            ],
        },
        regions=["us-east-1", "us-west-2"],
    )

    # One scored control, counted as High rather than Medium.
    assert "0 of 1 scored controls passed" in _tile(html, "Overall")[1]
    assert _severity_pass_rate(html, "high") == "0.0%"
    # No Medium control exists, so its pass rate is the empty-set default.
    assert _severity_pass_rate(html, "medium") == "0%"


def test_agent_registry_global_rows_get_a_risk_card_without_a_region():
    """Region == "Global" AR rows are their own risk card, not a region.

    AR-01 and AR-02 are account-scoped IAM checks tagged Global. They must show
    their own risk card, and Global must not be counted as a scanned region.
    """
    html = _render(
        {
            "bedrock": [
                _finding("BR-01", "High", "Failed", "bedrock", "us-east-1"),
            ],
            "agent-registry": [
                _finding("AR-01", "High", "Failed", "agent-registry", "Global"),
                _finding("AR-02", "Medium", "Failed", "agent-registry", "Global"),
                _finding("AR-05", "High", "Failed", "agent-registry", "us-west-2"),
            ],
        },
        regions=["us-east-1", "us-west-2"],
    )

    assert "1 High" in _risk_card(html, "us-east-1")
    assert "1 High" in _risk_card(html, "us-west-2")
    global_card = _risk_card(html, "Global")
    assert "1 High" in global_card
    assert "1 Med" in global_card
    # Global must not inflate the scanned-region count.
    assert re.search(r"Visible rows across (\d+) regions", html).group(1) == "2"


def test_agent_registry_counts_reach_the_area_tile_and_navigation():
    """The Agent Registry tile and nav entry report its own totals."""
    html = _render(
        {
            "agentcore": [_finding("AC-01", "High", "Failed", "agentcore")],
            "agent-registry": [
                _finding("AR-01", "High", "Failed", "agent-registry"),
                _finding("AR-05", "Medium", "Passed", "agent-registry"),
                _finding("AR-07", "Informational", "N/A", "agent-registry"),
            ],
        }
    )

    value, sub = _tile(html, "AWS Agent Registry")
    assert value == "3"
    assert "1 Failed" in sub and "1 Passed" in sub and "1 N/A" in sub
    # AgentCore must not absorb the Agent Registry rows.
    assert _tile(html, "AgentCore")[0] == "1"
    nav = re.search(r"<h3>By Service</h3>(.*?)</nav>", html, re.S).group(1)
    registry_nav = re.search(
        r'<a href="#agent-registry" class="nav-item">(.*?)</a>', nav, re.S
    )
    assert registry_nav, "AWS Agent Registry navigation entry missing"
    assert '<span class="count">3</span>' in registry_nav.group(1)


def test_contextual_rows_are_excluded_from_the_agent_registry_score():
    """AG-* rows derived from AR-* controls are contextual, not scored.

    AG-33..AG-38 restate Agent Registry findings for the Agentic AI lens. They
    must be reported as lens rows so the same evidence is not counted twice.
    """
    html = _render(
        {
            "agent-registry": [
                _finding("AR-03", "Medium", "Failed", "agent-registry"),
            ],
            "agentic": [
                _finding("AG-33", "Medium", "Failed", "agentic"),
            ],
        }
    )

    value, sub = _tile(html, "Lens / Compliance Rows")
    assert value == "1"
    assert "1 failed" in sub
    # Only AR-03 is scored; AG-33 restates it.
    assert "1 of 1 scored controls passed" not in _tile(html, "Overall")[1]
    assert "0 of 1 scored controls passed" in _tile(html, "Overall")[1]
