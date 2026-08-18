"""Evidence-discipline tests for the corrected FinServ controls.

Each control here previously described or scored more than the AWS API response
actually shows. These tests pin the corrected behavior and, more importantly,
assert the *absence* of the specific overclaims — so a future edit that
reinstates one fails rather than silently shipping.

Covers FS-28, FS-39, FS-40, FS-41, and FS-67.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from .support import finserv_app as app
from .support import make_resource_inventory


def _statuses(result) -> set:
    return {row["Status"] for row in result["csv_data"]}


def _blob(result) -> str:
    return " ".join(
        f"{row['Finding']} {row['Finding_Details']} {row['Resolution']}"
        for row in result["csv_data"]
    )


def _guardrail_inventory(topic_policy: dict):
    return make_resource_inventory(
        guardrails=app.GuardrailInventory(
            summaries=[{"id": "g1", "name": "example-guard"}],
            detail_by_id={"g1": {"topicPolicy": topic_policy}},
        )
    )


def _content_policy_guardrail_inventory(content_policy: dict):
    return make_resource_inventory(
        guardrails=app.GuardrailInventory(
            summaries=[{"id": "g1", "name": "example-guard"}],
            detail_by_id={"g1": {"contentPolicy": content_policy}},
        )
    )


# ---------------------------------------------------------------------------
# FS-28 — an absent tier must be reported as unknown, never assumed CLASSIC.
# ---------------------------------------------------------------------------


class TestFS28TierIsObservedNotAssumed:
    def test_absent_tier_is_reported_unknown(self):
        inv = _guardrail_inventory({"topics": [{"name": "advice", "type": "DENY"}]})
        result = app.check_guardrail_denied_topics_financial(inv)
        blob = _blob(result)
        assert "tier unknown" in blob
        assert "not assumed CLASSIC" in blob
        # The affirmative claim "reports the CLASSIC tier" must not appear; the
        # only permitted mention of CLASSIC is the explicit disclaimer above.
        assert "report the CLASSIC tier" not in blob
        assert "CLASSIC tier supports" not in blob

    def test_absent_tier_does_not_produce_the_classic_finding(self):
        inv = _guardrail_inventory({"topics": [{"name": "advice", "type": "DENY"}]})
        result = app.check_guardrail_denied_topics_financial(inv)
        names = [row["Finding"] for row in result["csv_data"]]
        assert "Topic Policies Configured on CLASSIC Tier" not in names

    def test_explicit_classic_tier_is_still_reported(self):
        inv = _guardrail_inventory(
            {
                "topics": [{"name": "advice", "type": "DENY"}],
                "tier": {"tierName": "CLASSIC"},
            }
        )
        result = app.check_guardrail_denied_topics_financial(inv)
        names = [row["Finding"] for row in result["csv_data"]]
        assert "Topic Policies Configured on CLASSIC Tier" in names

    def test_finding_names_do_not_claim_financial_topic_coverage(self):
        """Neither regulated-advice coverage nor topic type is inspected."""
        inv = _guardrail_inventory({"topics": []})
        result = app.check_guardrail_denied_topics_financial(inv)
        names = " ".join(row["Finding"] for row in result["csv_data"])
        assert "Denied Financial" not in names
        assert "Denied Topics" not in names

    def test_passed_finding_carries_the_manual_review_qualifier(self):
        inv = _guardrail_inventory(
            {
                "topics": [{"name": "advice", "type": "DENY"}],
                "tier": {"tierName": "STANDARD"},
            }
        )
        result = app.check_guardrail_denied_topics_financial(inv)
        assert "does not establish coverage" in _blob(result)

    def test_mixed_tier_results_disclose_the_unknown_tier_guardrail(self):
        """P1 regression: `elif topics_classic_tier` used to win unconditionally
        whenever any guardrail was CLASSIC, silently omitting a *different*
        guardrail whose tier is unknown from the finding entirely — reporting
        Passed with no tier-unknown disclosure at all."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[
                    {"id": "g1", "name": "classic-guard"},
                    {"id": "g2", "name": "unknown-guard"},
                ],
                detail_by_id={
                    "g1": {
                        "topicPolicy": {
                            "topics": [{"name": "advice", "type": "DENY"}],
                            "tier": {"tierName": "CLASSIC"},
                        }
                    },
                    "g2": {
                        "topicPolicy": {
                            "topics": [{"name": "advice", "type": "DENY"}],
                        }
                    },
                },
            )
        )
        result = app.check_guardrail_denied_topics_financial(inv)
        names = [row["Finding"] for row in result["csv_data"]]
        assert "Topic Policies Configured on CLASSIC Tier" in names
        blob = _blob(result)
        assert "unknown-guard" in blob
        assert "tier unknown" in blob
        assert "not assumed CLASSIC" in blob


# ---------------------------------------------------------------------------
# FS-36 — same defect as FS-28, on contentPolicy.tier instead of topicPolicy.tier.
# An absent tier must be reported as unknown, never assumed CLASSIC.
# ---------------------------------------------------------------------------


class TestFS36TierIsObservedNotAssumed:
    def test_absent_tier_is_reported_unknown(self):
        inv = _content_policy_guardrail_inventory(
            {"filters": [{"type": "HATE", "inputStrength": "HIGH"}]}
        )
        result = app.check_guardrail_content_filters(inv)
        blob = _blob(result)
        assert "tier unknown" in blob
        assert "not assumed CLASSIC" in blob

    def test_absent_tier_does_not_produce_the_classic_finding(self):
        inv = _content_policy_guardrail_inventory(
            {"filters": [{"type": "HATE", "inputStrength": "HIGH"}]}
        )
        result = app.check_guardrail_content_filters(inv)
        names = [row["Finding"] for row in result["csv_data"]]
        assert "Guardrail Content Filters on CLASSIC Tier" not in names

    def test_explicit_classic_tier_is_still_reported(self):
        inv = _content_policy_guardrail_inventory(
            {
                "filters": [{"type": "HATE", "inputStrength": "HIGH"}],
                "tier": {"tierName": "CLASSIC"},
            }
        )
        result = app.check_guardrail_content_filters(inv)
        names = [row["Finding"] for row in result["csv_data"]]
        assert "Guardrail Content Filters on CLASSIC Tier" in names

    def test_explicit_standard_tier_still_passes_without_a_classic_claim(self):
        inv = _content_policy_guardrail_inventory(
            {
                "filters": [{"type": "HATE", "inputStrength": "HIGH"}],
                "tier": {"tierName": "STANDARD"},
            }
        )
        result = app.check_guardrail_content_filters(inv)
        names = [row["Finding"] for row in result["csv_data"]]
        assert "Guardrails With Content Filters Found" in names
        assert "Guardrail Content Filters on CLASSIC Tier" not in names
        assert "tier unknown" not in _blob(result)

    def test_mixed_tier_results_disclose_the_unknown_tier_guardrail(self):
        """P1 regression: `elif guardrails_classic_tier` used to win
        unconditionally whenever any guardrail was CLASSIC, silently omitting
        a *different* guardrail whose tier is unknown from the finding
        entirely — reporting Passed with no tier-unknown disclosure."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[
                    {"id": "g1", "name": "classic-guard"},
                    {"id": "g2", "name": "unknown-guard"},
                ],
                detail_by_id={
                    "g1": {
                        "contentPolicy": {
                            "filters": [{"type": "HATE", "inputStrength": "HIGH"}],
                            "tier": {"tierName": "CLASSIC"},
                        }
                    },
                    "g2": {
                        "contentPolicy": {
                            "filters": [{"type": "HATE", "inputStrength": "HIGH"}],
                        }
                    },
                },
            )
        )
        result = app.check_guardrail_content_filters(inv)
        names = [row["Finding"] for row in result["csv_data"]]
        assert "Guardrail Content Filters on CLASSIC Tier" in names
        blob = _blob(result)
        assert "unknown-guard" in blob
        assert "tier unknown" in blob
        assert "not assumed CLASSIC" in blob


# ---------------------------------------------------------------------------
# FS-51 — same defect as FS-28, on the PROMPT_ATTACK filter's contentPolicy.tier.
# ---------------------------------------------------------------------------


class TestFS51TierIsObservedNotAssumed:
    def test_absent_tier_is_reported_unknown(self):
        inv = _content_policy_guardrail_inventory(
            {"filters": [{"type": "PROMPT_ATTACK", "inputStrength": "HIGH"}]}
        )
        result = app.check_prompt_injection_input_validation(inv)
        blob = _blob(result)
        assert "tier unknown" in blob
        assert "not assumed CLASSIC" in blob

    def test_absent_tier_does_not_produce_the_classic_finding(self):
        inv = _content_policy_guardrail_inventory(
            {"filters": [{"type": "PROMPT_ATTACK", "inputStrength": "HIGH"}]}
        )
        result = app.check_prompt_injection_input_validation(inv)
        names = [row["Finding"] for row in result["csv_data"]]
        assert "Prompt Attack Filters on CLASSIC Tier" not in names

    def test_explicit_classic_tier_is_still_reported(self):
        inv = _content_policy_guardrail_inventory(
            {
                "filters": [{"type": "PROMPT_ATTACK", "inputStrength": "HIGH"}],
                "tier": {"tierName": "CLASSIC"},
            }
        )
        result = app.check_prompt_injection_input_validation(inv)
        names = [row["Finding"] for row in result["csv_data"]]
        assert "Prompt Attack Filters on CLASSIC Tier" in names

    def test_mixed_tier_results_disclose_the_unknown_tier_guardrail(self):
        """P1 regression: `elif guardrails_classic_tier_pa` used to win
        unconditionally whenever any guardrail was CLASSIC, silently omitting
        a *different* guardrail whose tier is unknown from the finding
        entirely — reporting Passed with no tier-unknown disclosure."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[
                    {"id": "g1", "name": "classic-guard"},
                    {"id": "g2", "name": "unknown-guard"},
                ],
                detail_by_id={
                    "g1": {
                        "contentPolicy": {
                            "filters": [
                                {"type": "PROMPT_ATTACK", "inputStrength": "HIGH"}
                            ],
                            "tier": {"tierName": "CLASSIC"},
                        }
                    },
                    "g2": {
                        "contentPolicy": {
                            "filters": [
                                {"type": "PROMPT_ATTACK", "inputStrength": "HIGH"}
                            ],
                        }
                    },
                },
            )
        )
        result = app.check_prompt_injection_input_validation(inv)
        names = [row["Finding"] for row in result["csv_data"]]
        assert "Prompt Attack Filters on CLASSIC Tier" in names
        blob = _blob(result)
        assert "unknown-guard" in blob
        assert "tier unknown" in blob
        assert "not assumed CLASSIC" in blob


# ---------------------------------------------------------------------------
# FS-59 — same defect as FS-28, on the off-topic allowlist's topicPolicy.tier.
# ---------------------------------------------------------------------------


class TestFS59TierIsObservedNotAssumed:
    def test_absent_tier_is_reported_unknown(self):
        inv = _guardrail_inventory({"topics": [{"name": "off-topic", "type": "DENY"}]})
        result = app.check_guardrail_topic_allowlist(inv)
        blob = _blob(result)
        assert "tier unknown" in blob
        assert "not assumed CLASSIC" in blob

    def test_absent_tier_does_not_produce_the_classic_finding(self):
        inv = _guardrail_inventory({"topics": [{"name": "off-topic", "type": "DENY"}]})
        result = app.check_guardrail_topic_allowlist(inv)
        names = [row["Finding"] for row in result["csv_data"]]
        assert "Topic Restrictions Configured on CLASSIC Tier" not in names

    def test_explicit_classic_tier_is_still_reported(self):
        inv = _guardrail_inventory(
            {
                "topics": [{"name": "off-topic", "type": "DENY"}],
                "tier": {"tierName": "CLASSIC"},
            }
        )
        result = app.check_guardrail_topic_allowlist(inv)
        names = [row["Finding"] for row in result["csv_data"]]
        assert "Topic Restrictions Configured on CLASSIC Tier" in names

    def test_mixed_tier_results_disclose_the_unknown_tier_guardrail(self):
        """P1 regression: `elif topics_classic_tier` used to win unconditionally
        whenever any guardrail was CLASSIC, silently omitting a *different*
        guardrail whose tier is unknown from the finding entirely — reporting
        Passed with no tier-unknown disclosure."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[
                    {"id": "g1", "name": "classic-guard"},
                    {"id": "g2", "name": "unknown-guard"},
                ],
                detail_by_id={
                    "g1": {
                        "topicPolicy": {
                            "topics": [{"name": "off-topic", "type": "DENY"}],
                            "tier": {"tierName": "CLASSIC"},
                        }
                    },
                    "g2": {
                        "topicPolicy": {
                            "topics": [{"name": "off-topic", "type": "DENY"}],
                        }
                    },
                },
            )
        )
        result = app.check_guardrail_topic_allowlist(inv)
        names = [row["Finding"] for row in result["csv_data"]]
        assert "Topic Restrictions Configured on CLASSIC Tier" in names
        blob = _blob(result)
        assert "unknown-guard" in blob
        assert "tier unknown" in blob
        assert "not assumed CLASSIC" in blob


# ---------------------------------------------------------------------------
# FS-39 / FS-41 — MonitoringScheduleStatus has no "Active" value. The running
# state is "Scheduled"; anything else must not be reported as running.
# ---------------------------------------------------------------------------

CLARIFY_CASES = [
    ("ModelBias", "check_sagemaker_clarify_bias", "FS-39"),
    ("ModelExplainability", "check_sagemaker_clarify_explainability", "FS-41"),
]


def _schedule(monitoring_type: str, status: str, name: str = "sched-1"):
    return {
        "MonitoringScheduleName": name,
        "MonitoringScheduleArn": f"arn:aws:sagemaker:us-east-1:123456789012:monitoring-schedule/{name}",
        "MonitoringScheduleStatus": status,
        "EndpointName": "endpoint-1",
        "MonitoringType": monitoring_type,
    }


@pytest.mark.parametrize("monitoring_type,func_name,check_id", CLARIFY_CASES)
class TestClarifySchedulesReportObservedStatus:
    @patch("finserv_app.boto3.client")
    def test_never_claims_active(
        self, mock_client, monitoring_type, func_name, check_id
    ):
        c = MagicMock()
        c.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": [_schedule(monitoring_type, "Scheduled")]
        }
        mock_client.return_value = c
        result = getattr(app, func_name)()
        blob = _blob(result)
        assert "Monitoring Active" not in blob
        assert "Explainability Active" not in blob

    @patch("finserv_app.boto3.client")
    def test_scheduled_status_passes_and_is_reported(
        self, mock_client, monitoring_type, func_name, check_id
    ):
        c = MagicMock()
        c.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": [_schedule(monitoring_type, "Scheduled")]
        }
        mock_client.return_value = c
        result = getattr(app, func_name)()
        assert "Passed" in _statuses(result)
        assert "Failed" not in _statuses(result)
        assert "Scheduled" in _blob(result)

    @patch("finserv_app.boto3.client")
    def test_stopped_schedule_is_not_reported_as_running(
        self, mock_client, monitoring_type, func_name, check_id
    ):
        """The original defect: a Stopped schedule scored as a clean pass."""
        c = MagicMock()
        c.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": [_schedule(monitoring_type, "Stopped")]
        }
        mock_client.return_value = c
        result = getattr(app, func_name)()
        assert "Failed" in _statuses(result)
        assert result["status"] == "WARN"
        assert "Stopped" in _blob(result)

    @patch("finserv_app.boto3.client")
    def test_endpoint_name_is_surfaced(
        self, mock_client, monitoring_type, func_name, check_id
    ):
        c = MagicMock()
        c.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": [_schedule(monitoring_type, "Scheduled")]
        }
        mock_client.return_value = c
        result = getattr(app, func_name)()
        assert "endpoint-1" in _blob(result)

    @patch("finserv_app.boto3.client")
    def test_carries_manual_review_qualifier(
        self, mock_client, monitoring_type, func_name, check_id
    ):
        c = MagicMock()
        c.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": [_schedule(monitoring_type, "Scheduled")]
        }
        mock_client.return_value = c
        result = getattr(app, func_name)()
        assert "review manually" in _blob(result)


# ---------------------------------------------------------------------------
# FS-40 — advisory only, zero API calls. Must never be described as automated.
# ---------------------------------------------------------------------------


class TestFS40StaysAdvisory:
    @patch("finserv_app.boto3.client")
    def test_makes_no_api_calls(self, mock_client):
        result = app.check_bedrock_evaluation_bias_datasets()
        mock_client.assert_not_called()
        assert _statuses(result) == {"N/A"}

    def test_finding_keeps_the_advisory_prefix(self):
        result = app.check_bedrock_evaluation_bias_datasets()
        assert all(
            row["Finding"].startswith("ADVISORY: ") for row in result["csv_data"]
        )

    def test_never_claims_validation(self):
        blob = _blob(result=app.check_bedrock_evaluation_bias_datasets())
        for word in ("Validated", "validates", "automatically verifies"):
            assert word not in blob
        assert "cannot be inspected via API" in blob


# ---------------------------------------------------------------------------
# FS-67 — configuration hint only, and the assessment must not assess itself.
# ---------------------------------------------------------------------------


class TestFS67IsAHintAndExcludesItself:
    def test_reports_hint_not_enforcement(self):
        inv = make_resource_inventory(
            lambda_functions=[
                {
                    "FunctionName": "customer-agent-action-handler",
                    "Environment": {"Variables": {"MAX_TRANSACTION_AMOUNT": "500"}},
                }
            ]
        )
        result = app.check_agent_financial_transaction_thresholds(inv)
        blob = _blob(result)
        assert "not evidence that a limit is enforced" in blob
        assert "MAX_RETRIES" in blob

    def test_passed_name_no_longer_claims_threshold_configuration(self):
        inv = make_resource_inventory(
            lambda_functions=[
                {
                    "FunctionName": "customer-agent-action-handler",
                    "Environment": {"Variables": {"MAX_RETRIES": "3"}},
                }
            ]
        )
        result = app.check_agent_financial_transaction_thresholds(inv)
        names = [row["Finding"] for row in result["csv_data"]]
        assert "Agent Action-Group Lambdas Have Threshold Configuration" not in names
        assert "Agent Action-Group Lambdas Have Threshold-Named Variables" in names

    @patch.dict(
        "os.environ",
        {
            "AWS_LAMBDA_FUNCTION_NAME": "aiml-security-aiml-sec-123456789012-FinServAssessment"
        },
    )
    def test_excludes_the_assessments_own_lambda(self):
        """The assessment's own function matches on both 'finserv' and 'agent'."""
        inv = make_resource_inventory(
            lambda_functions=[
                {
                    "FunctionName": "aiml-security-aiml-sec-123456789012-FinServAssessment",
                    "Environment": {"Variables": {}},
                },
                {
                    # Synthetic Lambda name, not a credential. detect-secrets
                    # reads it as a base64 high-entropy string.
                    "FunctionName": "aiml-security-aiml-sec-123456789012-OWASPAssessment",  # pragma: allowlist secret
                    "Environment": {"Variables": {}},
                },
            ]
        )
        result = app.check_agent_financial_transaction_thresholds(inv)
        blob = _blob(result)
        assert "FinServAssessment" not in blob
        assert "OWASPAssessment" not in blob
        assert _statuses(result) == {"N/A"}

    @patch.dict(
        "os.environ",
        {
            "AWS_LAMBDA_FUNCTION_NAME": "aiml-security-aiml-sec-123456789012-FinServAssessment"
        },
    )
    def test_still_assesses_customer_lambdas_alongside_its_own(self):
        inv = make_resource_inventory(
            lambda_functions=[
                {
                    "FunctionName": "aiml-security-aiml-sec-123456789012-FinServAssessment",
                    "Environment": {"Variables": {}},
                },
                {
                    "FunctionName": "customer-bedrock-agent-tool",
                    "Environment": {"Variables": {}},
                },
            ]
        )
        result = app.check_agent_financial_transaction_thresholds(inv)
        blob = _blob(result)
        assert "customer-bedrock-agent-tool" in blob
        assert "FinServAssessment" not in blob

    def test_self_exclusion_is_inert_without_the_lambda_env_var(self):
        """Outside Lambda there is no self to exclude, so nothing is dropped."""
        assert app._self_lambda_name_prefix() in ("",)
        inv = make_resource_inventory(
            lambda_functions=[
                {"FunctionName": "some-agent-fn", "Environment": {"Variables": {}}}
            ]
        )
        result = app.check_agent_financial_transaction_thresholds(inv)
        assert "some-agent-fn" in _blob(result)

    @patch.dict(
        "os.environ", {"AWS_LAMBDA_FUNCTION_NAME": "totally-unrelated-function"}
    )
    def test_unrecognized_own_name_disables_self_exclusion(self):
        assert app._self_lambda_name_prefix() == ""
        assert app._is_assessment_own_lambda("anything") is False
