"""Tests for deterministic PDF report modeling and rendering."""

import os
import sys


REPORT_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment",
        "functions",
        "security",
        "generate_consolidated_report",
    )
)
if REPORT_DIR not in sys.path:
    sys.path.insert(0, REPORT_DIR)

from pdf_report import generate_pdf_report  # noqa: E402
from report_model import build_report_model, classify_theme  # noqa: E402


def _finding(
    check_id,
    finding,
    *,
    service,
    status,
    severity,
    account="111122223333",
    region="us-east-1",
    details="Resource arn:aws:service:us-east-1:111122223333:thing/example.",
    resolution="Apply the documented security control.",
    reference="https://docs.aws.amazon.com/",
    frameworks=None,
):
    row = {
        "Check_ID": check_id,
        "Finding": finding,
        "Finding_Details": details,
        "Resolution": resolution,
        "Reference": reference,
        "Severity": severity,
        "Status": status,
        "Region": region,
        "Account_ID": account,
        "_service": service,
    }
    if frameworks is not None:
        # Responsible AI GRC rows carry this extra column; the report layer
        # must tolerate it on some rows and not others.
        row["Compliance_Frameworks"] = frameworks
    return row


def _across_accounts(findings, accounts):
    """Repeat every row for each account, as a multi-account scan would."""
    repeated = []
    for account in accounts:
        for finding in findings:
            row = dict(finding)
            row["Account_ID"] = account
            repeated.append(row)
    return repeated


def _report_data():
    findings = [
        _finding(
            "BR-01",
            "Bedrock model invocation permissions are scoped",
            service="bedrock",
            status="Passed",
            severity="High",
            region="Global",
            details=(
                "IAM policies granting Amazon Bedrock model invocation are restricted "
                "to approved principals and model resources in account 111122223333."
            ),
            resolution="No action required; retain least-privilege policy reviews.",
        ),
        _finding(
            "BR-04",
            "Bedrock API activity is not fully logged",
            service="bedrock",
            status="Failed",
            severity="Medium",
            region="Global",
            details=(
                "The organization trail does not include the required Amazon Bedrock "
                "data events, reducing visibility into model invocation activity."
            ),
            resolution=(
                "Enable the applicable CloudTrail data event selectors, centralize "
                "the logs, and validate retention and alerting."
            ),
        ),
        _finding(
            "BR-05",
            "Bedrock guardrails enforce content safeguards",
            service="bedrock",
            status="Passed",
            severity="High",
            details=(
                "Guardrail arn:aws:bedrock:us-east-1:111122223333:guardrail/gr-a1b2c3 "
                "has content filters and denied-topic policies enabled."
            ),
            resolution="No action required; continue testing safeguards before release.",
        ),
        _finding(
            "BR-12",
            "Knowledge base storage lacks a customer-managed KMS key",
            service="bedrock",
            status="Failed",
            severity="High",
            details=(
                "Knowledge base kb-synthetic-01 uses provider-managed encryption for "
                "its vector-store data rather than the required customer-managed key."
            ),
            resolution=(
                "Migrate the knowledge base storage to a customer-managed KMS key and "
                "restrict key administration and usage permissions."
            ),
        ),
        _finding(
            "BR-18",
            "Bedrock prompt management is unavailable in this region",
            service="bedrock",
            status="N/A",
            severity="Informational",
            region="us-west-2",
            details=(
                "The prompt management API was not available in us-west-2 during the "
                "assessment, so this control could not be evaluated there."
            ),
            resolution="Re-evaluate when the feature is available in this region.",
        ),
        _finding(
            "BR-23",
            "Bedrock interface endpoints restrict private connectivity",
            service="bedrock",
            status="Passed",
            severity="Medium",
            details=(
                "Interface endpoint vpce-0a1b2c3d4e5f67890 is attached to approved "
                "private subnets and restrictive security groups."
            ),
            resolution="No action required; monitor endpoint policy changes.",
        ),
        _finding(
            "SM-01",
            "SageMaker notebook storage uses customer-managed encryption",
            service="sagemaker",
            status="Passed",
            severity="High",
            details=(
                "Notebook instance ml-secure-notebook encrypts its attached storage "
                "with arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555."
            ),
            resolution="No action required; retain key rotation and access reviews.",
        ),
        _finding(
            "SM-02",
            "SageMaker training job permits network access",
            service="sagemaker",
            status="Failed",
            severity="Medium",
            details=(
                "Training job customer-churn-training has network isolation disabled, "
                "allowing the training container to make outbound network requests."
            ),
            resolution=(
                "Enable network isolation where supported and provide required data "
                "through approved private storage and VPC paths."
            ),
        ),
        _finding(
            "SM-03",
            "SageMaker execution role is overly permissive",
            service="sagemaker",
            status="Failed",
            severity="High",
            details=(
                "Role arn:aws:iam::111122223333:role/SyntheticSageMakerExecutionRole "
                "grants wildcard S3 and IAM actions beyond the workload's requirements."
            ),
            resolution=(
                "Replace wildcard grants with resource-scoped permissions and add "
                "preventive policy checks to the role deployment pipeline."
            ),
        ),
        _finding(
            "SM-08",
            "SageMaker endpoint monitoring is configured",
            service="sagemaker",
            status="Passed",
            severity="Medium",
            details=(
                "Endpoint fraud-detection-endpoint publishes invocation metrics and "
                "has alarms for error rate and latency anomalies."
            ),
            resolution="No action required; periodically test alarm routing.",
        ),
        _finding(
            "SM-14",
            "SageMaker inference capacity has scaling controls",
            service="sagemaker",
            status="Passed",
            severity="Low",
            details=(
                "Endpoint fraud-detection-endpoint uses bounded auto scaling with "
                "configured minimum and maximum capacity."
            ),
            resolution="No action required; review capacity and budget thresholds.",
        ),
        _finding(
            "SM-20",
            "No applicable SageMaker model package groups were found",
            service="sagemaker",
            status="N/A",
            severity="Informational",
            region="us-west-2",
            details=(
                "No model package groups were discovered in us-west-2, so package "
                "approval controls were not applicable in that regional scope."
            ),
            resolution="No action required unless model package groups are introduced.",
        ),
        _finding(
            "AC-01",
            "AgentCore gateway authorization is not caller constrained",
            service="agentcore",
            status="Failed",
            severity="High",
            details=(
                "Gateway arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/"
                "gw-a1b2c3 uses a JWT authorizer without an allowed audience or scope."
            ),
            resolution=(
                "Constrain the authorizer to approved audiences, clients, scopes, or "
                "claims and verify rejected-caller test cases."
            ),
        ),
        _finding(
            "AC-07",
            "AgentCore token vault uses customer-managed encryption",
            service="agentcore",
            status="Passed",
            severity="High",
            details=(
                "Token vault tv-a1b2c3 is encrypted with a customer-managed KMS key "
                "whose policy is limited to the runtime service role."
            ),
            resolution="No action required; retain key and role access reviews.",
        ),
        _finding(
            "AC-11",
            "Agent runtime observability is incomplete",
            service="agentcore",
            status="Failed",
            severity="Medium",
            details=(
                "Runtime customer-support-agent emits application logs but has no "
                "alarm for repeated tool authorization failures."
            ),
            resolution=(
                "Create security-focused metrics and alarms for denied tool calls, "
                "authentication failures, and anomalous invocation volume."
            ),
        ),
        _finding(
            "AC-18",
            "Agent Registry publication bypasses manual approval",
            service="agentcore",
            status="Failed",
            severity="Medium",
            region="Global",
            details=(
                "Registry production-agents automatically approves submitted records, "
                "allowing publication without an independent governance review."
            ),
            resolution=(
                "Remove auto-approval rules and require documented manual approval "
                "before records can enter the approved lifecycle state."
            ),
        ),
        _finding(
            "AC-21",
            "Agent Registry organization discovery is governed",
            service="agentcore",
            status="Passed",
            severity="Medium",
            region="Global",
            details=(
                "Registry production-agents limits organization discovery to "
                "o-a1b2c3d4e5 and records the discovery source."
            ),
            resolution="No action required; review organization scope periodically.",
        ),
        _finding(
            "AC-24",
            "AgentCore runtime uses private VPC connectivity",
            service="agentcore",
            status="Passed",
            severity="Medium",
            details=(
                "Runtime customer-support-agent is attached to private subnets with "
                "no direct public route and uses approved VPC endpoints."
            ),
            resolution="No action required; monitor route and security-group drift.",
        ),
        _finding(
            "FS-01",
            "Responsible AI ownership and review are documented",
            service="responsible-ai-grc",
            status="Passed",
            severity="Medium",
            region="Global",
            frameworks="FFIEC CAT | SR 11-7",
            details=(
                "The synthetic workload inventory records an accountable owner, model "
                "purpose, intended users, and approval date."
            ),
            resolution="No action required; refresh the review after material changes.",
        ),
        _finding(
            "FS-09",
            "Model transparency documentation is incomplete",
            service="responsible-ai-grc",
            status="Failed",
            severity="Low",
            region="Global",
            frameworks="FFIEC CAT | SR 11-7 | ISO 27001 A.12.6",
            details=(
                "The model card documents intended use and limitations but does not "
                "record evaluation results for known demographic performance slices."
            ),
            resolution=(
                "Add the available evaluation results, known limitations, and an "
                "owner-approved plan for unresolved measurement gaps."
            ),
        ),
        _finding(
            "AG-01",
            "Agentic AI caller authorization mapping",
            service="agentic",
            status="Failed",
            severity="High",
            details=(
                "Contextual mapping of AC-01: the agent gateway does not constrain JWT "
                "callers to approved audiences or scopes."
            ),
            resolution="Apply the remediation recorded for direct finding AC-01.",
        ),
        _finding(
            "AG-12",
            "Agentic AI security telemetry mapping",
            service="agentic",
            status="Failed",
            severity="Medium",
            details=(
                "Contextual mapping of AC-11: security monitoring does not alert on "
                "repeated tool authorization failures."
            ),
            resolution="Apply the remediation recorded for direct finding AC-11.",
        ),
        _finding(
            "AG-33",
            "Agentic AI registry approval mapping",
            service="agentic",
            status="Failed",
            severity="Medium",
            region="Global",
            details=(
                "Contextual mapping of AC-18: agent records can be approved without a "
                "manual publication decision."
            ),
            resolution="Apply the remediation recorded for direct finding AC-18.",
        ),
        _finding(
            "OW-01",
            "OWASP prompt injection safeguards mapping",
            service="owasp",
            status="Passed",
            severity="High",
            details=(
                "Contextual mapping of BR-05: Bedrock guardrail content safeguards "
                "are enabled for the assessed generative AI application."
            ),
            resolution="No action required; continue adversarial prompt testing.",
        ),
        _finding(
            "OW-05",
            "OWASP improper output handling telemetry mapping",
            service="owasp",
            status="Failed",
            severity="Medium",
            details=(
                "Contextual mapping of BR-04 and AC-11: telemetry gaps reduce the "
                "ability to detect unsafe or unauthorized AI interactions."
            ),
            resolution="Apply the remediation recorded for BR-04 and AC-11.",
        ),
        _finding(
            "OW-06",
            "OWASP excessive agency authorization mapping",
            service="owasp",
            status="Failed",
            severity="High",
            details=(
                "Contextual mapping of AC-01 and SM-03: caller and execution-role "
                "permissions are broader than the assessed workload requires."
            ),
            resolution="Apply the remediation recorded for AC-01 and SM-03.",
        ),
    ]
    stats = {
        "bedrock": {"passed": 3, "failed": 2, "na": 1},
        "sagemaker": {"passed": 3, "failed": 2, "na": 1},
        "agentcore": {"passed": 3, "failed": 3, "na": 0},
        "responsible-ai-grc": {"passed": 1, "failed": 1, "na": 0},
        "agentic": {"passed": 0, "failed": 3, "na": 0},
        "owasp": {"passed": 1, "failed": 2, "na": 0},
    }
    return findings, stats


def _single_account_model(findings, stats):
    return build_report_model(
        all_findings=findings,
        service_stats=stats,
        mode="single",
        account_id="111122223333",
        timestamp="September 02, 2026 12:00:00 UTC",
        regions=["us-east-1"],
        contextual_services={"agentic", "owasp"},
    )


def test_report_model_excludes_contextual_mappings_from_direct_posture():
    findings, stats = _report_data()
    model = build_report_model(
        all_findings=findings,
        service_stats=stats,
        mode="single",
        account_id="111122223333",
        timestamp="September 02, 2026 12:00:00 UTC",
        regions=["us-east-1"],
        contextual_services={"agentic", "owasp"},
    )

    assert model["metrics"]["direct_rows"] == 20
    assert model["metrics"]["contextual_rows"] == 6
    assert model["metrics"]["failed_high"] == 3
    assert model["metrics"]["passed_scored"] == 10
    assert model["metrics"]["pass_rate"] == 55.6
    assert model["posture"]["tone"] == "high"
    assert model["has_global_scope"] is True
    assert model["accounts"] == ["111122223333"]


def test_report_model_builds_broad_deterministic_themes_and_priorities():
    findings, stats = _report_data()
    model = build_report_model(
        all_findings=findings,
        service_stats=stats,
        mode="single",
        account_id="111122223333",
        timestamp="September 02, 2026 12:00:00 UTC",
        regions=["us-east-1"],
        contextual_services={"agentic", "owasp"},
    )

    strength_names = {theme["name"] for theme in model["strengths"]}
    assert "AI safety and abuse prevention" in strength_names
    # A theme with any failed row is a concern, never a strength, so the KMS
    # gap in BR-12 keeps data protection out of the strengths list.
    assert "Data protection and privacy" not in strength_names
    concern_names = [theme["name"] for theme in model["concerns"]]
    assert concern_names[0] == "Identity and access management"
    assert "Data protection and privacy" in concern_names
    assert model["priorities"][0]["check_id"] == "AC-01"
    assert model["priorities"][0]["accounts"] == ["111122223333"]
    assert model["priorities"][0]["regions"] == ["us-east-1"]


def test_theme_classification_uses_headline_over_remediation_prose():
    """Remediation text that mentions an adjacent control must not win.

    BR-12 is an encryption finding whose resolution mentions key *permissions*,
    and AC-11 is an observability finding whose details mention tool
    *authorization* failures.  Both previously classified as identity and
    access management because the first matching rule won outright.
    """
    findings, _stats = _report_data()
    by_check = {finding["Check_ID"]: finding for finding in findings}

    assert classify_theme(by_check["BR-12"]) == "Data protection and privacy"
    assert classify_theme(by_check["AC-11"]) == "Logging, monitoring, and assurance"
    assert classify_theme(by_check["SM-03"]) == "Identity and access management"
    assert classify_theme(by_check["AC-24"]) == "Network and workload isolation"
    assert classify_theme(by_check["BR-05"]) == "AI safety and abuse prevention"
    assert classify_theme(by_check["AC-18"]) == "Governance and software supply chain"


def test_theme_classification_falls_back_when_no_keywords_match():
    finding = _finding(
        "BR-99",
        "Assessed control produced no recognizable signal",
        service="bedrock",
        status="Failed",
        severity="Low",
        details="The assessed configuration differs from the expected baseline.",
        resolution="Review the configuration with the service owner.",
    )

    assert classify_theme(finding) == "General security posture"


def test_report_model_breaks_failed_rows_down_by_area_and_severity():
    findings, stats = _report_data()
    model = _single_account_model(findings, stats)

    areas = model["area_severity"]
    # Ordered by weighted severity (high*9 + medium*3 + low), so AgentCore's
    # one high plus two mediums outranks Bedrock's one high plus one medium.
    assert [area["slug"] for area in areas] == [
        "agentcore",
        "bedrock",
        "sagemaker",
        "responsible-ai-grc",
    ]
    assert areas[0]["high"] == 1
    assert areas[0]["medium"] == 2
    assert areas[0]["low"] == 0
    assert areas[0]["total"] == 3
    assert areas[0]["weighted"] == 15
    assert sum(area["total"] for area in areas) == model["metrics"]["failed_scored"]
    # Contextual AG-/OW- rows never reach the chart, so no area is named for them.
    assert {area["slug"] for area in areas}.isdisjoint({"agentic", "owasp"})


def test_report_model_cross_tabulates_themes_against_areas():
    findings, stats = _report_data()
    model = _single_account_model(findings, stats)

    matrix = model["theme_matrix"]
    assert matrix["services"] == sorted(matrix["services"])
    by_theme = {row["theme"]: row for row in matrix["rows"]}
    iam = by_theme["Identity and access management"]
    assert iam["total"] == 2
    assert len(iam["counts"]) == len(matrix["services"])
    assert sum(iam["counts"]) == iam["total"]
    assert sum(matrix["totals"]) == model["metrics"]["failed_scored"]


def test_report_model_reports_catalog_coverage_per_area():
    findings, stats = _report_data()
    model = _single_account_model(findings, stats)

    coverage = {entry["slug"]: entry for entry in model["coverage"]}
    assert coverage["bedrock"]["represented"] == 6
    assert coverage["bedrock"]["catalog_total"] == 40
    assert coverage["bedrock"]["not_represented"] == 34
    assert coverage["bedrock"]["coverage_rate"] == 15.0
    # Areas ordered as the assessment reports them, not alphabetically.
    assert list(model["coverage"])[0]["slug"] == "bedrock"


def test_report_model_explains_why_rows_are_not_applicable():
    findings, stats = _report_data()
    model = _single_account_model(findings, stats)

    reasons = {entry["reason"]: entry for entry in model["na_reasons"]}
    # A regional API gap and an empty inventory are different coverage stories,
    # and neither may be reported as an access problem.
    assert reasons["API or feature unavailable in scope"]["checks"] == ["BR-18"]
    assert reasons["No applicable resources"]["checks"] == ["SM-20"]
    assert "Access not permitted" not in reasons


def test_report_model_rolls_up_frameworks_and_owasp_categories():
    findings, stats = _report_data()
    model = _single_account_model(findings, stats)

    frameworks = {entry["framework"]: entry for entry in model["compliance_frameworks"]}
    assert frameworks["FFIEC CAT"]["checks"] == 2
    assert frameworks["FFIEC CAT"]["passed"] == 1
    assert frameworks["FFIEC CAT"]["failed"] == 1
    assert frameworks["FFIEC CAT"]["low"] == 1
    assert frameworks["FFIEC CAT"]["pass_rate"] == 50.0
    assert frameworks["ISO 27001 A.12.6"]["pass_rate"] == 0.0

    categories = {entry["category"]: entry for entry in model["owasp_rollup"]}
    assert categories["LLM01:2025 Prompt Injection"]["passed"] == 1
    assert categories["LLM06:2025 Excessive Agency"]["high"] == 1
    assert categories["LLM05:2025 Improper Output Handling"]["checks"] == ["OW-05"]


def test_report_model_groups_shared_remediation_across_checks():
    shared = (
        "Replace wildcard grants with resource-scoped permissions and add "
        "preventive policy checks to the deployment pipeline."
    )
    findings = [
        _finding(
            "SM-03",
            "SageMaker execution role is overly permissive",
            service="sagemaker",
            status="Failed",
            severity="High",
            resolution=shared,
        ),
        _finding(
            "BR-02",
            "Bedrock invocation role is overly permissive",
            service="bedrock",
            status="Failed",
            severity="Medium",
            resolution=shared.upper(),
        ),
        _finding(
            "AC-11",
            "Agent runtime observability is incomplete",
            service="agentcore",
            status="Failed",
            severity="Medium",
            resolution="Create security-focused metrics and alarms.",
        ),
    ]
    stats = {
        "bedrock": {"passed": 0, "failed": 1, "na": 0},
        "sagemaker": {"passed": 0, "failed": 1, "na": 0},
        "agentcore": {"passed": 0, "failed": 1, "na": 0},
    }
    model = _single_account_model(findings, stats)

    leverage = model["remediation_leverage"]
    # Only the group spanning two checks is reported; the lone AC-11 resolution
    # would just restate its own finding.
    assert len(leverage) == 1
    assert leverage[0]["checks"] == ["BR-02", "SM-03"]
    assert leverage[0]["rows"] == 2
    assert leverage[0]["high"] == 1
    assert leverage[0]["medium"] == 1
    assert leverage[0]["services"] == ["Amazon Bedrock", "Amazon SageMaker AI"]


def test_report_model_scores_accounts_and_marks_systemic_prevalence():
    findings, stats = _report_data()
    accounts = ["111122223333", "444455556666"]
    model = build_report_model(
        all_findings=_across_accounts(findings, accounts),
        service_stats=stats,
        mode="multi",
        account_ids=accounts,
        timestamp="September 02, 2026 12:00:00 UTC",
        regions=["us-east-1"],
        contextual_services={"agentic", "owasp"},
    )

    scorecard = model["account_scorecard"]
    assert [entry["account"] for entry in scorecard] == accounts
    assert scorecard[0]["failed"] == 8
    assert scorecard[0]["passed"] == 10
    assert scorecard[0]["na"] == 2
    assert scorecard[0]["high"] == 3
    assert scorecard[0]["weighted_score"] == 40
    assert scorecard[0]["pass_rate"] == 55.6
    assert scorecard[0]["leading_theme"] == "Identity and access management"

    # The same gap in every assessed account is a baseline problem, so it is
    # reported as systemic rather than as two isolated resources.
    assert model["priorities"][0]["check_id"] == "AC-01"
    assert model["priorities"][0]["accounts"] == accounts
    assert model["priorities"][0]["prevalence"]["label"] == "Systemic"


def test_report_model_collapses_repeated_rows_into_grouped_entries():
    findings, stats = _report_data()
    accounts = ["111122223333", "444455556666"]
    model = build_report_model(
        all_findings=_across_accounts(findings, accounts),
        service_stats=stats,
        mode="multi",
        account_ids=accounts,
        timestamp="September 02, 2026 12:00:00 UTC",
        regions=["us-east-1"],
        contextual_services={"agentic", "owasp"},
    )

    groups = model["finding_groups"]
    assert len(groups) == len(findings)
    assert model["metrics"]["total_rows"] == len(findings) * 2
    by_check = {group["check_id"]: group for group in groups}
    assert by_check["AC-01"]["rows"] == 2
    assert by_check["AC-01"]["accounts"] == accounts
    # Identical evidence in both accounts collapses to one variant; distinct
    # evidence would be preserved separately.
    assert len(by_check["AC-01"]["variants"]) == 1
    assert by_check["AC-01"]["variants"][0]["accounts"] == accounts


def test_pdf_renderer_generates_complete_pdf_bytes():
    findings, stats = _report_data()
    pdf = generate_pdf_report(
        all_findings=findings,
        service_stats=stats,
        mode="multi",
        account_ids=["111122223333", "444455556666"],
        timestamp="September 02, 2026 12:00:00 UTC",
        regions=["us-east-1"],
        contextual_services={"agentic", "owasp"},
    )

    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert len(pdf) > 5_000


def test_pdf_renderer_omits_charts_when_nothing_failed():
    """A clean account has no failed rows, so both charts have no data.

    The charts must be omitted rather than rendered empty, and the surrounding
    sections must still produce a complete document.
    """
    findings = [
        _finding(
            "BR-01",
            "Bedrock model invocation permissions are scoped",
            service="bedrock",
            status="Passed",
            severity="High",
            resolution="No action required.",
        ),
        _finding(
            "SM-20",
            "No applicable SageMaker model package groups were found",
            service="sagemaker",
            status="N/A",
            severity="Informational",
            details="No model package groups were discovered in us-east-1.",
            resolution="No action required unless model package groups are introduced.",
        ),
    ]
    stats = {
        "bedrock": {"passed": 1, "failed": 0, "na": 0},
        "sagemaker": {"passed": 0, "failed": 0, "na": 1},
    }
    model = _single_account_model(findings, stats)
    assert model["area_severity"] == []
    assert model["theme_matrix"]["rows"] == []
    assert model["priorities"] == []

    pdf = generate_pdf_report(
        all_findings=findings,
        service_stats=stats,
        mode="single",
        account_ids=["111122223333"],
        timestamp="September 02, 2026 12:00:00 UTC",
        regions=["us-east-1"],
        contextual_services={"agentic", "owasp"},
    )
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")


def test_pdf_renderer_emits_navigable_outline():
    """The contents page and the PDF outline come from one heading pass.

    ``multiBuild`` lays the story out twice so headings can report the page they
    landed on; if that pass regressed, the document would still render but would
    carry no outline entries at all.
    """
    findings, stats = _report_data()
    pdf = generate_pdf_report(
        all_findings=findings,
        service_stats=stats,
        mode="single",
        account_ids=["111122223333"],
        timestamp="September 02, 2026 12:00:00 UTC",
        regions=["us-east-1"],
        contextual_services={"agentic", "owasp"},
    )

    assert b"/Outlines" in pdf
    assert pdf.count(b"/Title") > 10
