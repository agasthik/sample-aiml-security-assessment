import unittest
import copy
import os
import sys
import importlib.util
from unittest import mock


_THIS_DIR = os.path.dirname(__file__)
_SAVED_SYS_PATH = list(sys.path)
_SAVED_REPORT_TEMPLATE = sys.modules.get("report_template")

try:
    if _THIS_DIR not in sys.path:
        sys.path.insert(0, _THIS_DIR)

    _template_spec = importlib.util.spec_from_file_location(
        "generate_report_template", os.path.join(_THIS_DIR, "report_template.py")
    )
    generate_report_template = importlib.util.module_from_spec(_template_spec)
    sys.modules["report_template"] = generate_report_template
    _template_spec.loader.exec_module(generate_report_template)

    _app_spec = importlib.util.spec_from_file_location(
        "generate_consolidated_report_app", os.path.join(_THIS_DIR, "app.py")
    )
    generate_report_app = importlib.util.module_from_spec(_app_spec)
    sys.modules["generate_consolidated_report_app"] = generate_report_app
    _app_spec.loader.exec_module(generate_report_app)
finally:
    sys.path[:] = _SAVED_SYS_PATH
    if _SAVED_REPORT_TEMPLATE is None:
        sys.modules.pop("report_template", None)
    else:
        sys.modules["report_template"] = _SAVED_REPORT_TEMPLATE


generate_html_report = generate_report_app.generate_html_report
generate_report_direct = generate_report_template.generate_html_report


def _data(html):
    """The data model the Cloudscape UI renders, embedded in the page."""
    return generate_report_template.extract_report_data(html)


def _nav(html):
    """Navigation heading -> area slugs, in order."""
    return {g["heading"]: g["areas"] for g in _data(html)["navGroups"]}


def _area(html, slug):
    return next((a for a in _data(html)["areas"] if a["slug"] == slug), None)


def _scope_groups(html):
    return {
        g["label"]: [c["label"] for c in g["chips"]]
        for g in _data(html)["methodology"]["scopeGroups"]
    }


def _scope_links(html):
    return [
        segment
        for segment in _data(html)["methodology"]["source"]
        if isinstance(segment, dict) and "link" in segment
    ]


class TestHtmlReportGeneration(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_reports"
        if not os.path.exists(self.test_dir):
            os.makedirs(self.test_dir)

        self.test_assessment_results = {
            "account_id": "123456789012",
            "timestamp": "2026-04-17 10:00:00 UTC",
            "bedrock": {
                "bedrock_security_report": [
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "BR-01",
                        "Finding": "Bedrock Model Access Control",
                        "Finding_Details": "The Bedrock model access is not restricted to specific IAM principals. This could allow unauthorized access to model endpoints.",
                        "Resolution": "Implement IAM policies to restrict access to specific principals and use resource-based policies for model invocations.",
                        "Reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        "Severity": "High",
                        "Status": "Failed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "BR-04",
                        "Finding": "Bedrock API Logging",
                        "Finding_Details": "CloudTrail logging is not enabled for Bedrock API calls. This limits audit capabilities and incident investigation.",
                        "Resolution": "Enable CloudTrail logging for Bedrock API actions and configure log retention policies.",
                        "Reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html",
                        "Severity": "Medium",
                        "Status": "Failed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "BR-05",
                        "Finding": "Bedrock Guardrails Check",
                        "Finding_Details": "Guardrails are properly configured for content filtering.",
                        "Resolution": "No action required",
                        "Reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html",
                        "Severity": "Informational",
                        "Status": "Passed",
                    },
                ]
            },
            "sagemaker": {
                "sagemaker_security_report": [
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "SM-01",
                        "Finding": "SageMaker Endpoint Encryption",
                        "Finding_Details": "SageMaker endpoint is not using encryption at rest. Sensitive data could be exposed if storage is compromised.",
                        "Resolution": "Enable AWS KMS encryption for SageMaker endpoints using customer managed keys.",
                        "Reference": "https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html",
                        "Severity": "High",
                        "Status": "Failed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "SM-02",
                        "Finding": "SageMaker Network Isolation",
                        "Finding_Details": "SageMaker training jobs are not configured with network isolation. This could expose the training environment to external networks.",
                        "Resolution": "Enable network isolation for SageMaker training jobs and use VPC configurations.",
                        "Reference": "https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html",
                        "Severity": "Medium",
                        "Status": "Failed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "SM-03",
                        "Finding": "SageMaker IAM Role Permissions",
                        "Finding_Details": "SageMaker execution role has overly permissive IAM policies. This violates the principle of least privilege.",
                        "Resolution": "Review and restrict IAM role permissions to only necessary actions and resources.",
                        "Reference": "https://docs.aws.amazon.com/sagemaker/latest/dg/security_iam_id-based-policy-examples.html",
                        "Severity": "High",
                        "Status": "Failed",
                    },
                ]
            },
            "agentcore": {
                "agentcore_security_report": [
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "AC-01",
                        "Finding": "AgentCore IAM Identity Center Check",
                        "Finding_Details": "AWS IAM Identity Center is properly configured.",
                        "Resolution": "No action required",
                        "Reference": "https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html",
                        "Severity": "Informational",
                        "Status": "Passed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "AR-03",
                        "Finding": "Agent Registry Publication Approval Governance",
                        "Finding_Details": "Registry 'production-agents' (reg-a1b2c3) automatically approves submitted records.",
                        "Resolution": "Remove auto-approval rules so submitted records require manual review.",
                        "Reference": "https://docs.aws.amazon.com/agent-registry-control/latest/APIReference/API_ApprovalConfiguration.html",
                        "Severity": "Medium",
                        "Status": "Failed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "AR-04",
                        "Finding": "Agent Registry Discovery Authorization",
                        "Finding_Details": "Registry 'production-agents' (reg-a1b2c3) uses a custom JWT authorizer without a caller constraint.",
                        "Resolution": "Configure at least one allowed audience, client, scope, or custom claim.",
                        "Reference": "https://docs.aws.amazon.com/agent-registry-control/latest/APIReference/API_CustomJWTAuthorizerConfiguration.html",
                        "Severity": "High",
                        "Status": "Failed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "AR-05",
                        "Finding": "Agent Registry Customer-Managed KMS Encryption",
                        "Finding_Details": "Registry 'production-agents' uses the default AWS owned key.",
                        "Resolution": "Create a replacement registry with a customer-managed KMS key.",
                        "Reference": "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/registry-data-encryption.html",
                        "Severity": "Medium",
                        "Status": "Failed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "AR-06",
                        "Finding": "Agent Registry Organization Auto-Detection",
                        "Finding_Details": "Registry 'production-agents' has active organization-scoped auto-detection.",
                        "Resolution": "No action required",
                        "Reference": "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/registry-organizations.html",
                        "Severity": "Medium",
                        "Status": "Passed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "AR-07",
                        "Finding": "Agent Registry Record Lifecycle Governance",
                        "Finding_Details": "Registry record 'payment-agent' is in the governed APPROVED lifecycle state.",
                        "Resolution": "No action required",
                        "Reference": "https://docs.aws.amazon.com/agent-registry-control/latest/APIReference/API_SubmitRegistryRecordForApproval.html",
                        "Severity": "Medium",
                        "Status": "Passed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "AR-08",
                        "Finding": "Agent Registry Record Provenance",
                        "Finding_Details": "Auto-detected registry record 'payment-agent' does not include valid DETECTED_FROM provenance.",
                        "Resolution": "Refresh or recreate the auto-detected record.",
                        "Reference": "https://docs.aws.amazon.com/agent-registry-control/latest/APIReference/API_Provenance.html",
                        "Severity": "Medium",
                        "Status": "Failed",
                    },
                ]
            },
        }

    def test_generate_viewable_report(self):
        """Generate a viewable HTML report with test data"""
        report_data = copy.deepcopy(self.test_assessment_results)
        report_data["agentcore"]["agentcore_security_report"].extend(
            [
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "AG-33",
                    "Finding": "Agentic AI Registry Publication Approval Governance",
                    "Finding_Details": "Registry publication does not require manual approval.",
                    "Resolution": "Require manual review for registry publication.",
                    "Reference": "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html",
                    "Severity": "Medium",
                    "Status": "Failed",
                },
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "AG-34",
                    "Finding": "Agentic AI Registry Discovery Authorization",
                    "Finding_Details": "Registry discovery authorization is not constrained to intended callers.",
                    "Resolution": "Constrain registry discovery authorization.",
                    "Reference": "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html",
                    "Severity": "High",
                    "Status": "Failed",
                },
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "AG-35",
                    "Finding": "Agentic AI Registry Metadata Encryption",
                    "Finding_Details": "Registry metadata uses the default AWS owned key.",
                    "Resolution": "Create the registry with a customer-managed KMS key.",
                    "Reference": "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html",
                    "Severity": "Medium",
                    "Status": "Failed",
                },
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "AG-36",
                    "Finding": "Agentic AI Organization Discovery Coverage",
                    "Finding_Details": "Organization-scoped registry auto-detection is active.",
                    "Resolution": "No action required",
                    "Reference": "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html",
                    "Severity": "Medium",
                    "Status": "Passed",
                },
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "AG-37",
                    "Finding": "Agentic AI Registry Record Lifecycle Governance",
                    "Finding_Details": "The registry record is in the governed APPROVED state.",
                    "Resolution": "No action required",
                    "Reference": "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html",
                    "Severity": "Medium",
                    "Status": "Passed",
                },
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "AG-38",
                    "Finding": "Agentic AI Registry Record Provenance",
                    "Finding_Details": "The auto-detected record is missing source lineage.",
                    "Resolution": "Restore runtime or gateway provenance.",
                    "Reference": "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html",
                    "Severity": "Medium",
                    "Status": "Failed",
                },
            ]
        )
        html_content = generate_html_report(report_data)

        # Save the HTML content to a file
        report_path = os.path.join(self.test_dir, "security_report.html")
        with open(report_path, "w") as f:
            f.write(html_content)

        print(f"\nReport generated at: {os.path.abspath(report_path)}")

        # Optionally open the report in the default browser
        # webbrowser.open('file://' + os.path.abspath(report_path))

        # Verify file exists and has content
        self.assertTrue(os.path.exists(report_path))
        self.assertTrue(os.path.getsize(report_path) > 0)

        # Basic content checks
        with open(report_path, "r") as f:
            content = f.read()
            # Bedrock findings
            self.assertIn("Bedrock Model Access Control", content)
            self.assertIn("Bedrock API Logging", content)

            # SageMaker findings
            self.assertIn("SageMaker Endpoint Encryption", content)
            self.assertIn("SageMaker Network Isolation", content)
            self.assertIn("SageMaker IAM Role Permissions", content)

            # AgentCore findings
            self.assertIn("AgentCore IAM Identity Center Check", content)
            self.assertIn("Agent Registry Publication Approval Governance", content)
            self.assertIn("Agent Registry Discovery Authorization", content)
            # The area card and scope chip both carry the service icon.
            registry = _area(content, "agent-registry")
            self.assertEqual(registry["name"], "AWS Agent Registry")
            self.assertEqual(
                registry["icon"],
                generate_report_template.svg_data_uri(
                    generate_report_template.AGENT_REGISTRY_ICON
                ),
            )
            registry_chip = next(
                chip
                for group in _data(content)["methodology"]["scopeGroups"]
                for chip in group["chips"]
                if chip["label"] == "AWS Agent Registry"
            )
            self.assertEqual(registry_chip["icon"], registry["icon"])
            self.assertIn(
                "Agentic AI Registry Publication Approval Governance", content
            )
            self.assertIn("Agentic AI Registry Discovery Authorization", content)

            # Severity levels
            self.assertIn("High", content)
            self.assertIn("Medium", content)

            # The page is the self-contained Cloudscape UI plus its data.
            data = _data(content)
            self.assertEqual(data["kind"], "assessment")
            self.assertEqual(data["mode"], "single")
            self.assertIn('<div id="root">', content)
            self.assertIn('<link rel="icon" type="image/svg+xml"', content)
            self.assertNotIn("fonts.googleapis.com", content)
            self.assertIn("awsui", content)  # Cloudscape component styles
            self.assertEqual(
                [f["label"] for f in data["filters"]["areas"]][:4],
                ["Bedrock", "SageMaker", "AgentCore", "AWS Agent Registry"],
            )

            # Overview, legend and default filter.
            labels = [m["label"] for m in data["overview"]]
            self.assertIn("Lens / Compliance Rows", labels)
            self.assertIn(
                "Direct failed service rows",
                [m["description"] for m in data["overview"]],
            )
            self.assertEqual(
                [row["severity"] for row in data["severityLegend"]],
                ["High", "Medium", "Low", "Informational"],
            )
            self.assertEqual(data["filters"]["defaultStatus"], "failed")
            # Single-account reports offer no account filter.
            self.assertIsNone(data["filters"]["accounts"])

    def test_generate_multi_account_report(self):
        """Test multi-account report generation using shared template directly"""
        # Create test data in multi-account format
        all_findings = [
            {
                "account_id": "111122223333",
                "check_id": "BR-01",
                "finding": "Test Finding 1",
                "details": "Details 1",
                "resolution": "Fix it",
                "reference": "https://example.com",
                "severity": "High",
                "status": "Failed",
                "_service": "bedrock",
            },
            {
                "account_id": "444455556666",
                "check_id": "SM-01",
                "finding": "Test Finding 2",
                "details": "Details 2",
                "resolution": "Fix it",
                "reference": "https://example.com",
                "severity": "Medium",
                "status": "Failed",
                "_service": "sagemaker",
            },
            {
                "account_id": "111122223333",
                "check_id": "AC-01",
                "finding": "Test Finding 3",
                "details": "Details 3",
                "resolution": "N/A",
                "reference": "https://example.com",
                "severity": "Low",
                "status": "Passed",
                "_service": "agentcore",
            },
            {
                "account_id": "111122223333",
                "check_id": "AR-03",
                "finding": "Agent Registry Publication Approval Governance",
                "details": "Registry 'shared-agents' automatically approves submitted records.",
                "resolution": "Require manual review.",
                "reference": "https://example.com",
                "severity": "Medium",
                "status": "Failed",
                "_service": "agentcore",
            },
            {
                "account_id": "111122223333",
                "check_id": "AG-34",
                "finding": "Agentic AI Registry Discovery Authorization",
                "details": "Registry discovery JWT authorization is not constrained.",
                "resolution": "Constrain intended callers.",
                "reference": "https://example.com",
                "severity": "High",
                "status": "Failed",
                "_service": "agentic",
            },
            {
                "account_id": "444455556666",
                "check_id": "FS-01",
                "finding": "Responsible AI GRC Regional Scope Not Applicable",
                "details": "No regional AI/ML resources found.",
                "resolution": "No action required.",
                "reference": "https://example.com",
                "severity": "Informational",
                "status": "N/A",
                "_service": "responsible-ai-grc",
            },
        ]
        service_findings = {
            "bedrock": [all_findings[0]],
            "sagemaker": [all_findings[1]],
            "agentcore": [all_findings[2], all_findings[3]],
            "agentic": [all_findings[4]],
            "responsible-ai-grc": [all_findings[5]],
        }
        service_stats = {
            "bedrock": {"passed": 0, "failed": 1},
            "sagemaker": {"passed": 0, "failed": 1},
            "agentcore": {"passed": 1, "failed": 1},
            "agentic": {"passed": 0, "failed": 1},
            "responsible-ai-grc": {"passed": 0, "failed": 0, "na": 1},
        }

        html_content = generate_report_direct(
            all_findings=all_findings,
            service_findings=service_findings,
            service_stats=service_stats,
            mode="multi",
            account_ids=["111122223333", "444455556666"],
        )

        report_path = os.path.join(self.test_dir, "multi_account_report.html")
        with open(report_path, "w") as f:
            f.write(html_content)

        print(f"\nMulti-account report generated at: {os.path.abspath(report_path)}")

        self.assertTrue(os.path.exists(report_path))
        self.assertIn("Agent Registry Publication Approval Governance", html_content)
        self.assertIn("Agentic AI Registry Discovery Authorization", html_content)

        with open(report_path, "r") as f:
            content = f.read()
            # Multi-account specific
            self.assertIn("Multi-Account", content)
            self.assertIn("2 Accounts", content)
            data = _data(content)
            self.assertEqual(data["mode"], "multi")
            self.assertEqual(
                data["filters"]["accounts"], ["111122223333", "444455556666"]
            )
            self.assertEqual(
                [card["label"] for card in data["risk"]["accounts"]],
                ["111122223333", "444455556666"],
            )
            nav = _nav(content)
            self.assertEqual(nav["By Governance Framework"], ["responsible-ai-grc"])
            self.assertEqual(nav["By Lens"], ["agentic"])
            self.assertEqual(_area(content, "agentic")["name"], "Agentic AI Security")
            self.assertIn("Governance Framework", _scope_groups(content))
            self.assertNotIn("responsible-ai-grc", nav["By Service"])
            self.assertNotIn("Financial Services", content)

    def test_multi_account_report_renders_compliance_standards(self):
        """A multi-account report renders the AISF and OWASP sections only when
        their derived rows are present."""
        source = {
            "account_id": "111122223333",
            "region": "us-east-1",
            "check_id": "BR-20",
            "finding": "Knowledge Base Encryption",
            "details": "Details",
            "resolution": "Fix it",
            "reference": "https://example.com",
            "severity": "High",
            "status": "Failed",
            "_service": "bedrock",
        }
        aisf = dict(
            source,
            check_id="AISF-05",
            finding="AISF AIR-BDR-KB-03: Knowledge Base Vector Store Encryption",
            _service="aisf",
        )
        owasp = dict(
            source,
            account_id="444455556666",
            check_id="OW-01",
            finding="OWASP LLM01 Prompt Injection",
            _service="owasp",
        )
        failed = {"passed": 0, "failed": 1}

        without_derived = generate_report_direct(
            all_findings=[source],
            service_findings={"bedrock": [source]},
            service_stats={"bedrock": failed},
            mode="multi",
            account_ids=["111122223333", "444455556666"],
        )
        with_derived = generate_report_direct(
            all_findings=[source, aisf, owasp],
            service_findings={
                "bedrock": [source],
                "aisf": [aisf],
                "owasp": [owasp],
            },
            service_stats={"bedrock": failed, "aisf": failed, "owasp": failed},
            mode="multi",
            account_ids=["111122223333", "444455556666"],
        )

        report_path = os.path.join(
            self.test_dir, "multi_account_compliance_report.html"
        )
        with open(report_path, "w") as f:
            f.write(with_derived)
        print(f"\nMulti-account compliance report generated at: {report_path}")

        self.assertNotIn("By Compliance Standard", _nav(without_derived))
        self.assertIsNone(_area(without_derived, "aisf"))
        self.assertIn("2 Accounts", with_derived)
        self.assertEqual(
            _nav(with_derived)["By Compliance Standard"], ["owasp", "aisf"]
        )
        self.assertIsNotNone(_area(with_derived, "aisf"))
        self.assertIn("AWS AI Security Framework", with_derived)
        self.assertIn("AISF-05", with_derived)
        self.assertIn("OWASP Top 10", with_derived)
        self.assertIn("OW-01", with_derived)

    def test_missing_data_fields(self):
        """Test handling of assessment results with missing fields"""
        incomplete_data = {
            "account_id": "123456789012",
            "bedrock": {
                "bedrock_report": [
                    {"Finding": "Incomplete Bedrock Finding", "Severity": "High"}
                ]
            },
            "sagemaker": {},
            "agentcore": {},
        }

        html_content = generate_html_report(incomplete_data)

        # Save the HTML content to a file
        report_path = os.path.join(self.test_dir, "incomplete_report.html")
        with open(report_path, "w") as f:
            f.write(html_content)

        print(f"\nIncomplete data report generated at: {os.path.abspath(report_path)}")

        # The row is kept, with each missing field filled in, not dropped.
        data = _data(html_content)
        self.assertEqual(
            data["findings"],
            [
                {
                    "account": "",
                    "region": "",
                    "checkId": "",
                    "finding": "Incomplete Bedrock Finding",
                    "details": "",
                    "resolution": "",
                    "reference": None,
                    "severity": "High",
                    "status": "",
                    "service": "bedrock",
                }
            ],
        )
        overview = {m["label"]: m["value"] for m in data["overview"]}
        self.assertEqual(overview["Report Rows"], "1")
        # A row with no status is not a failure: no action item or alert.
        self.assertEqual(overview["Open Action Items"], "0")
        self.assertEqual(overview["Failed High"], "0")
        self.assertEqual(data["alerts"], [])

    def test_empty_findings(self):
        """Test handling of empty findings"""
        empty_data = {
            "account_id": "123456789012",
            "bedrock": {},
            "sagemaker": {},
            "agentcore": {},
        }

        html_content = generate_html_report(empty_data)
        report_path = os.path.join(self.test_dir, "empty_report.html")
        with open(report_path, "w") as f:
            f.write(html_content)

        print(f"\nEmpty data report generated at: {os.path.abspath(report_path)}")
        data = _data(html_content)
        self.assertEqual(data["kind"], "assessment")
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["alerts"], [])
        self.assertEqual(data["filters"]["defaultStatus"], "failed")
        # The core service areas are still shown, selected, with zero counts.
        core = ["bedrock", "sagemaker", "agentcore", "agent-registry"]
        self.assertEqual(_nav(html_content), {"By Service": core})
        self.assertEqual([o["value"] for o in data["filters"]["areas"]], core)
        self.assertEqual(
            [
                (
                    a["slug"],
                    a["selected"],
                    a["failed"],
                    a["passed"],
                    a["na"],
                    a["total"],
                )
                for a in data["areas"]
            ],
            [(slug, True, 0, 0, 0, 0) for slug in core],
        )
        self.assertEqual(
            {m["label"]: m["value"] for m in data["overview"]},
            {
                "Unique Check IDs": "0",
                "Report Rows": "0",
                "Open Action Items": "0",
                "Lens / Compliance Rows": "0",
                "Failed High": "0",
                "Failed Medium / Low": "0/0",
            },
        )
        self.assertEqual(
            data["risk"]["overall"]["description"], "0 of 0 scored controls passed"
        )

    def test_finserv_renders_when_present(self):
        """REQ-1: Responsible AI GRC findings render as a first-class service
        in the HTML."""
        data = dict(self.test_assessment_results)
        data["responsible-ai-grc"] = {
            "responsible_ai_grc_security_report": [
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "FS-01",
                    "Finding": "No Regional WAF Web ACLs Found",
                    "Finding_Details": "No WAF.",
                    "Resolution": "Add WAF.",
                    "Reference": "https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html",
                    "Severity": "Medium",
                    "Status": "Failed",
                    "Region": "region-a",
                },
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "FS-44",
                    "Finding": "Amazon Macie Enabled",
                    "Finding_Details": "Macie on.",
                    "Resolution": "None.",
                    "Reference": "https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html",
                    "Severity": "High",
                    "Status": "Passed",
                    "Region": "region-b",
                },
            ]
        }
        html = generate_html_report(data)
        report = _data(html)
        grc = _area(html, "responsible-ai-grc")
        self.assertEqual(grc["name"], "Responsible AI GRC")
        self.assertEqual(grc["sectionTitle"], "Responsible AI GRC Findings")
        self.assertIn(
            {"value": "responsible-ai-grc", "label": "Responsible AI GRC"},
            report["filters"]["areas"],
        )
        # GRC rows share the one findings table, keyed by their area.
        self.assertIn(
            ("FS-01", "responsible-ai-grc"),
            [(f["checkId"], f["service"]) for f in report["findings"]],
        )
        self.assertEqual(
            _scope_groups(html)["Governance Framework"], ["Responsible AI GRC"]
        )
        self.assertEqual(_nav(html)["By Governance Framework"], ["responsible-ai-grc"])
        self.assertIn(
            "wellarchitected/latest/generative-ai-lens/generative-ai-lens.html", html
        )
        self.assertIn(
            "introducing-the-updated-aws-user-guide-to-governance-risk-and-compliance-for-responsible-ai-adoption",
            html,
        )
        self.assertNotIn("global-FinServ-ComplianceGuide-GenAIRisks-public.pdf", html)
        self.assertNotIn("responsible-ai-grc", _nav(html)["By Service"])
        # The rebrand retires every "Financial Services" capability label,
        # and every legacy "finserv"/industry-* machine identity.
        self.assertNotIn("Financial Services Risk", html)
        self.assertNotIn("Financial Services GenAI Risk", html)
        self.assertNotIn("finserv", [a["slug"] for a in report["areas"]])
        self.assertNotIn("finserv", {f["service"] for f in report["findings"]})
        self.assertNotIn("By Industry", _nav(html))
        # Required non-Lens disambiguation must accompany the name.
        self.assertIn("is not the", html)
        self.assertIn("Responsible AI Lens", html)
        self.assertIn("eight focus areas", html)

    def test_finserv_omitted_when_absent(self):
        """REQ-1/REQ-7: with no Responsible AI GRC data the section is
        omitted cleanly."""
        html = generate_html_report(self.test_assessment_results)
        self.assertIsNone(_area(html, "responsible-ai-grc"))
        self.assertNotIn("By Governance Framework", _nav(html))
        self.assertNotIn(
            "responsible-ai-grc",
            [o["value"] for o in _data(html)["filters"]["areas"]],
        )
        # Only the Responsible AI GRC scope group is absent. The fixture carries
        # SM-01 and SM-03, two of the three source checks AISF control
        # AIR-SGM-TRN-05 derives from, so the derived AISF standard reports
        # incomplete coverage and renders the compliance scope group.
        self.assertNotIn("Governance Framework", _scope_groups(html))
        self.assertNotIn("Responsible AI GRC", html)
        self.assertIn(
            "wellarchitected/latest/generative-ai-lens/generative-ai-lens.html", html
        )
        self.assertNotIn(
            "introducing-the-updated-aws-user-guide-to-governance-risk-and-compliance-for-responsible-ai-adoption",
            html,
        )
        self.assertNotIn("global-FinServ-ComplianceGuide-GenAIRisks-public.pdf", html)
        # Other services still render (regression check).
        self.assertIsNotNone(_area(html, "bedrock"))

    def test_agentic_security_renders_when_present(self):
        """Agentic AI Security AG-* rows render as a first-class assessment area."""
        data = dict(self.test_assessment_results)
        data["bedrock"] = {
            "bedrock_security_report": [
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "BR-28",
                    "Finding": "Bedrock Agent Guardrail Association",
                    "Finding_Details": "Agent has a guardrail.",
                    "Resolution": "No action required.",
                    "Reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-use.html",
                    "Severity": "High",
                    "Status": "Passed",
                    "Region": "us-east-1",
                },
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "AG-01",
                    "Finding": "Agentic AI Agent Guardrail Association",
                    "Finding_Details": "Agentic AI security domain: Guardrail Enforcement.",
                    "Resolution": "Associate an approved Bedrock guardrail with each Bedrock agent.",
                    "Reference": "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html",
                    "Severity": "High",
                    "Status": "Passed",
                    "Region": "us-east-1",
                },
            ]
        }

        html = generate_html_report(data)

        report = _data(html)
        agentic = _area(html, "agentic")
        self.assertEqual(agentic["sectionTitle"], "Agentic AI Security Findings")
        self.assertIn(
            {"value": "agentic", "label": "Agentic AI Security"},
            report["filters"]["areas"],
        )
        self.assertEqual(_nav(html)["By Lens"], ["agentic"])
        self.assertIn(
            ("AG-01", "agentic"),
            [(f["checkId"], f["service"]) for f in report["findings"]],
        )
        self.assertIn(
            "wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html", html
        )
        # The Agentic AI Lens hyperlink in the methodology must appear exactly
        # once even when agentic findings are present (no duplicate link).
        self.assertEqual(
            [
                link["link"]
                for link in _scope_links(html)
                if link["link"] == "AWS Well-Architected Agentic AI Lens"
            ],
            ["AWS Well-Architected Agentic AI Lens"],
        )
        self.assertIn(
            "Human-in-the-loop governance",
            generate_report_template.rich_text(agentic["scope"]),
        )
        self.assertNotIn("agentic", _nav(html)["By Service"])

    def test_agentic_security_omitted_when_absent(self):
        """With no AG-* data the Agentic section is omitted cleanly."""
        html = generate_html_report(self.test_assessment_results)

        self.assertIsNone(_area(html, "agentic"))
        self.assertNotIn(
            "agentic", [o["value"] for o in _data(html)["filters"]["areas"]]
        )
        self.assertNotIn("By Lens", _nav(html))
        self.assertNotIn(
            "wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html", html
        )

    def test_region_risk_includes_global_scope_card(self):
        """Global failed findings render in risk by region / scope without inflating regions."""
        all_findings = [
            {
                "account_id": "123456789012",
                "check_id": "BR-01",
                "finding": "Regional Bedrock Check",
                "details": "No regional issue.",
                "resolution": "No action required.",
                "reference": "https://example.com",
                "severity": "High",
                "status": "Passed",
                "region": "us-east-1",
                "_service": "bedrock",
            },
            {
                "account_id": "123456789012",
                "check_id": "BR-03",
                "finding": "Marketplace Subscription Access Check",
                "details": "Overly permissive marketplace subscription access.",
                "resolution": "Restrict subscription access.",
                "reference": "https://example.com",
                "severity": "High",
                "status": "Failed",
                "region": "Global",
                "_service": "bedrock",
            },
            {
                "account_id": "123456789012",
                "check_id": "AC-09",
                "finding": "AgentCore Service-Linked Role Missing",
                "details": "Service-linked role is missing.",
                "resolution": "Allow service-linked role creation.",
                "reference": "https://example.com",
                "severity": "Medium",
                "status": "Failed",
                "region": "Global",
                "_service": "agentcore",
            },
        ]

        html = generate_report_direct(
            all_findings=all_findings,
            service_findings={
                "bedrock": all_findings[:2],
                "agentcore": [all_findings[2]],
            },
            service_stats={
                "bedrock": {"passed": 1, "failed": 1, "na": 0},
                "agentcore": {"passed": 0, "failed": 1, "na": 0},
            },
            mode="single",
            account_id="123456789012",
            regions=["eu-west-1", "us-east-1", "us-west-2"],
        )

        self.assertEqual(
            _data(html)["risk"]["regions"],
            [
                {"label": "eu-west-1", "total": 0, "high": 0, "medium": 0, "low": 0},
                {"label": "us-east-1", "total": 0, "high": 0, "medium": 0, "low": 0},
                {"label": "us-west-2", "total": 0, "high": 0, "medium": 0, "low": 0},
                {"label": "Global", "total": 2, "high": 1, "medium": 1, "low": 0},
            ],
        )
        # Global does not inflate the scanned region count.
        report_rows = next(
            m for m in _data(html)["overview"] if m["label"] == "Report Rows"
        )
        self.assertEqual(report_rows["description"], "Visible rows across 3 regions")

    def test_unique_control_scoring_does_not_weight_resource_rows(self):
        """Repeated resource passes count once while any control failure remains."""
        failed_control = {
            "account_id": "123456789012",
            "check_id": "BR-01",
            "finding": "Bedrock Access Control",
            "details": "One direct control failed.",
            "resolution": "Restrict access.",
            "reference": "https://example.com",
            "severity": "High",
            "status": "Failed",
            "region": "us-east-1",
            "_service": "bedrock",
        }
        record_passes = [
            {
                "account_id": "123456789012",
                "check_id": "AR-08",
                "finding": "Agent Registry Record Provenance",
                "details": f"Record {record_index} has valid provenance.",
                "resolution": "No action required.",
                "reference": "https://example.com",
                "severity": "Medium",
                "status": "Passed",
                "region": "us-east-1",
                "_service": "agentcore",
            }
            for record_index in range(100)
        ]

        html = generate_report_direct(
            all_findings=[failed_control, *record_passes],
            service_findings={
                "bedrock": [failed_control],
                "agentcore": record_passes,
            },
            service_stats={
                "bedrock": {"passed": 0, "failed": 1, "na": 0},
                "agentcore": {"passed": 100, "failed": 0, "na": 0},
            },
            mode="single",
            account_id="123456789012",
        )

        overall = _data(html)["risk"]["overall"]
        self.assertEqual(overall["passRateText"], "50.0%")
        self.assertEqual(overall["description"], "1 of 2 scored controls passed")
        self.assertNotIn("99.5%", html)

    def tearDown(self):
        """Clean up test files after running tests"""
        pass


class TestReportFailureHandling(unittest.TestCase):
    def setUp(self):
        self.event = {
            "Execution": {"Name": "synthetic-execution-id"},
            "OriginalInput": {
                "enableResponsibleAIGRC": "false",
                "enableOWASP": "false",
                "ResolvedRegions": {"regions": ["us-east-1"]},
            },
        }
        self.assessment_results = {
            "account_id": "123456789012",
            "timestamp": "2026-09-11 10:00:00 UTC",
            "bedrock": {
                "bedrock_security_report_synthetic-execution-id_us-east-1": [
                    {"Check_ID": "BR-00"}
                ]
            },
            "sagemaker": {
                "sagemaker_security_report_synthetic-execution-id_us-east-1": [
                    {"Check_ID": "SM-00"}
                ]
            },
            "agentcore": {
                "agentcore_security_report_synthetic-execution-id_us-east-1": [
                    {"Check_ID": "AC-00"}
                ]
            },
            "agent-registry": {
                "agent_registry_security_report_synthetic-execution-id_us-east-1": [
                    {"Check_ID": "AR-00"}
                ]
            },
        }

    def test_validation_rejects_a_missing_regional_artifact(self):
        self.event["OriginalInput"]["ResolvedRegions"]["regions"].append("us-west-2")

        with self.assertRaisesRegex(
            ValueError,
            "sagemaker_security_report_synthetic-execution-id_us-west-2.csv",
        ):
            generate_report_app.validate_assessment_artifacts(
                self.assessment_results,
                "synthetic-execution-id",
                self.event["OriginalInput"],
            )

    def test_validation_requires_responsible_ai_grc_as_owasp_dependency(self):
        self.event["OriginalInput"]["enableOWASP"] = "true"
        self.assessment_results["owasp"] = {
            "owasp_security_report_synthetic-execution-id_us-east-1": [
                {"Check_ID": "OW-01"}
            ]
        }

        with self.assertRaisesRegex(
            ValueError,
            "responsible_ai_grc_security_report_synthetic-execution-id.csv",
        ):
            generate_report_app.validate_assessment_artifacts(
                self.assessment_results,
                "synthetic-execution-id",
                self.event["OriginalInput"],
            )

    def test_generate_html_report_propagates_template_failure(self):
        with mock.patch.object(
            generate_report_app,
            "generate_report_from_template",
            side_effect=RuntimeError("template rendering failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "template rendering failed"):
                generate_report_app.generate_html_report(self.assessment_results)

    def test_handler_render_failure_uploads_nothing_and_cleans_cache(self):
        sts_client = mock.Mock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        s3_client = mock.Mock()
        s3_client.delete_object.side_effect = RuntimeError("cleanup failed")

        def boto_client(service_name, **_kwargs):
            return {"sts": sts_client, "s3": s3_client}[service_name]

        with (
            mock.patch.dict(
                os.environ,
                {"AIML_ASSESSMENT_BUCKET_NAME": "test-assessment-bucket"},
            ),
            mock.patch.object(
                generate_report_app.boto3,
                "client",
                side_effect=boto_client,
            ),
            mock.patch.object(
                generate_report_app,
                "get_assessment_results",
                return_value=self.assessment_results,
            ),
            mock.patch.object(
                generate_report_app,
                "generate_html_report",
                side_effect=RuntimeError("template rendering failed"),
            ),
            mock.patch.object(generate_report_app, "write_html_to_s3") as write_report,
        ):
            with self.assertRaisesRegex(RuntimeError, "template rendering failed"):
                generate_report_app.lambda_handler(self.event, None)

        write_report.assert_not_called()
        s3_client.delete_object.assert_called_once_with(
            Bucket="test-assessment-bucket",
            Key="permissions_cache_synthetic-execution-id.json",
        )

    def test_write_html_to_s3_propagates_upload_failure(self):
        s3_client = mock.Mock()
        s3_client.put_object.side_effect = RuntimeError("upload failed")

        with mock.patch.object(
            generate_report_app.boto3,
            "client",
            return_value=s3_client,
        ):
            with self.assertRaisesRegex(RuntimeError, "upload failed"):
                generate_report_app.write_html_to_s3(
                    "<html></html>",
                    "test-assessment-bucket",
                    "synthetic-execution-id",
                )

    def test_handler_success_still_returns_report_location(self):
        sts_client = mock.Mock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        s3_client = mock.Mock()

        def boto_client(service_name, **_kwargs):
            return {"sts": sts_client, "s3": s3_client}[service_name]

        with (
            mock.patch.dict(
                os.environ,
                {"AIML_ASSESSMENT_BUCKET_NAME": "test-assessment-bucket"},
            ),
            mock.patch.object(
                generate_report_app.boto3,
                "client",
                side_effect=boto_client,
            ),
            mock.patch.object(
                generate_report_app,
                "get_assessment_results",
                return_value=self.assessment_results,
            ),
            mock.patch.object(
                generate_report_app,
                "generate_html_report",
                return_value="<html></html>",
            ),
            mock.patch.object(
                generate_report_app,
                "write_html_to_s3",
                return_value="security_assessment_single_account_20260911_100000.html",
            ),
        ):
            response = generate_report_app.lambda_handler(self.event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(
            response["body"]["report_location"],
            (
                "s3://test-assessment-bucket/"
                "security_assessment_single_account_20260911_100000.html"
            ),
        )
        s3_client.delete_object.assert_called_once_with(
            Bucket="test-assessment-bucket",
            Key="permissions_cache_synthetic-execution-id.json",
        )


if __name__ == "__main__":
    unittest.main()
