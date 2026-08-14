"""Compatibility locks for report selectors, CSS classes, and deployment identities.

Phase 1 changed visible *labels* only and froze every machine identity. Phase 2
Stage 2b is the deliberate, reviewed exception: it renames the CloudFormation
logical ID, the physical Lambda name suffix, all four Step Functions state
names, and the ASL error result path, from FinServ-branded names to
Responsible AI GRC-branded names. Those renames are intentional breaking
changes — see docs/RESPONSIBLE_AI_GRC_PHASE2_STAGE2B_DESIGN.md — and this file
was updated to lock in the NEW values rather than deleted, per its own
principle below.

Everything NOT explicitly renamed by Stage 2b remains frozen: report
selectors, CSS classes, the "finserv" slug, the CSV filename prefix, and the
"aiml-security-" physical-name prefix (kept for a reason specific to Stage 2b
— see the physical-name test below) must not change here or in any future
phase without the same explicit, reviewed exception.

If an INTENTIONAL, reviewed rename makes one of these fail, update the
assertion to lock in the new value and record why in the commit — do not
silently delete the assertion. If an UNINTENTIONAL change makes one of these
fail, the change is wrong, not the test.
"""

import importlib.util
import json
import os
import sys

import pytest
import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORT_DIR = os.path.join(
    REPO_ROOT,
    "aiml-security-assessment",
    "functions",
    "security",
    "generate_consolidated_report",
)
TEMPLATE_PATH = os.path.join(REPO_ROOT, "aiml-security-assessment", "template.yaml")
TEMPLATE_MULTI_PATH = os.path.join(
    REPO_ROOT, "aiml-security-assessment", "template-multi-account.yaml"
)
ASL_PATH = os.path.join(
    REPO_ROOT, "aiml-security-assessment", "statemachine", "assessments.asl.json"
)

if REPORT_DIR not in sys.path:
    sys.path.insert(0, REPORT_DIR)

_spec = importlib.util.spec_from_file_location(
    "legacy_contract_report_template", os.path.join(REPORT_DIR, "report_template.py")
)
report_template = importlib.util.module_from_spec(_spec)
sys.modules["legacy_contract_report_template"] = report_template
_spec.loader.exec_module(report_template)


# ---------------------------------------------------------------------------
# CloudFormation: SAM templates parse with an intrinsic-tolerant loader.
# ---------------------------------------------------------------------------


class _CfnLoader(yaml.SafeLoader):
    """SafeLoader that tolerates CloudFormation short-form intrinsics."""


def _cfn_multi_constructor(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return {f"Fn::{tag_suffix}": loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {f"Fn::{tag_suffix}": loader.construct_sequence(node)}
    return {f"Fn::{tag_suffix}": loader.construct_mapping(node)}


_CfnLoader.add_multi_constructor("!", _cfn_multi_constructor)


def _load_template(path):
    with open(path) as handle:
        # _CfnLoader subclasses yaml.SafeLoader and adds only a multi-constructor
        # that turns CloudFormation short-form intrinsics (!Sub, !Ref, !GetAtt)
        # into plain dicts, so no arbitrary object instantiation is possible.
        # yaml.safe_load() cannot be used here: it hardcodes SafeLoader and gives
        # no way to register the intrinsic handler these templates require.
        return yaml.load(handle, Loader=_CfnLoader)  # nosec B506


@pytest.fixture(scope="module")
def template():
    return _load_template(TEMPLATE_PATH)


@pytest.fixture(scope="module")
def template_multi():
    return _load_template(TEMPLATE_MULTI_PATH)


@pytest.fixture(scope="module")
def asl():
    with open(ASL_PATH) as handle:
        return handle.read()


# ---------------------------------------------------------------------------
# Step Functions: all FOUR Responsible AI GRC state names are customer-visible
# in the console and in execution history. Renamed in Phase 2 Stage 2b from
# their FinServ-branded predecessors — this is the one reviewed exception to
# "state names don't change" the Phase 1 test suite otherwise enforced.
# ---------------------------------------------------------------------------

ASL_STATE_NAMES = [
    "Responsible AI GRC Enabled?",
    "Responsible AI GRC Security Assessment",
    "Responsible AI GRC Assessment Incomplete",
    "Responsible AI GRC Assessment Skipped",
]

RETIRED_ASL_STATE_NAMES = [
    "FinServ Enabled?",
    "FinServ Security Assessment",
    "FinServ Assessment Incomplete",
    "FinServ Assessment Skipped",
]


@pytest.mark.parametrize("state_name", ASL_STATE_NAMES)
def test_asl_state_names_are_frozen(asl, state_name):
    assert f'"{state_name}"' in asl


@pytest.mark.parametrize("state_name", RETIRED_ASL_STATE_NAMES)
def test_retired_finserv_asl_state_names_are_gone(asl, state_name):
    """The old names must not linger anywhere the ASL is compared byte-for-byte.

    A partial rename (some occurrences updated, some missed) is worse than no
    rename: it would leave dangling Next/Default references. Assert absence
    explicitly rather than relying on the presence assertions above alone.
    """
    assert f'"{state_name}"' not in asl


def test_asl_error_result_path_is_frozen(asl):
    assert '"ResultPath": "$.responsibleAIGRCError"' in asl


def test_retired_finserv_error_result_path_is_gone(asl):
    assert '"ResultPath": "$.finservError"' not in asl


def test_asl_lambda_substitution_is_frozen(asl):
    assert "${ResponsibleAIGRCAssessmentFunction}" in asl


def test_retired_finserv_lambda_substitution_is_gone(asl):
    assert "${FinServSecurityAssessmentFunction}" not in asl


def test_asl_is_a_substituted_template_not_plain_json(asl):
    """The ASL carries unquoted CloudFormation substitutions.

    e.g. `"MaxConcurrency": ${MaxRegionConcurrency}` — so the file is NOT valid
    JSON on its own and must not be parsed with json.loads by tooling. It
    becomes valid only after SAM performs DefinitionSubstitutions.
    """
    with pytest.raises(json.JSONDecodeError):
        json.loads(asl)
    assert "${MaxRegionConcurrency}" in asl


def test_asl_state_names_fit_the_step_functions_limit():
    """State names are capped at 80 characters."""
    for state_name in ASL_STATE_NAMES:
        assert len(state_name) <= 80


# ---------------------------------------------------------------------------
# CloudFormation identities: renaming the logical ID or FunctionName forces a
# Lambda replacement, changing ARNs, permissions, logs, and rollback behavior.
#
# Phase 2 Stage 2b renamed both, deliberately, as a reviewed CloudFormation
# replacement (see docs/RESPONSIBLE_AI_GRC_PHASE2_STAGE2B_DESIGN.md). The
# "aiml-security-" physical-name PREFIX is intentionally UNCHANGED — see
# test_own_lambda_prefix_matches_self_exclusion_assumption below for why.
# ---------------------------------------------------------------------------

LOGICAL_ID = "ResponsibleAIGRCAssessmentFunction"
RETIRED_LOGICAL_ID = "FinServSecurityAssessmentFunction"


def test_logical_id_is_frozen(template, template_multi):
    assert LOGICAL_ID in template["Resources"]
    assert LOGICAL_ID in template_multi["Resources"]


def test_retired_logical_id_is_gone(template, template_multi):
    assert RETIRED_LOGICAL_ID not in template["Resources"]
    assert RETIRED_LOGICAL_ID not in template_multi["Resources"]


def test_physical_function_name_is_frozen(template):
    function_name = template["Resources"][LOGICAL_ID]["Properties"]["FunctionName"]
    assert function_name == {
        "Fn::Sub": "aiml-security-${AWS::StackName}-RAIGRCAssessment"
    }


def test_own_lambda_prefix_matches_self_exclusion_assumption():
    """The "aiml-security-" prefix must survive Stage 2b unchanged.

    finserv_assessments/app.py's _self_lambda_name_prefix() derives the FS-67
    self-exclusion prefix by checking AWS_LAMBDA_FUNCTION_NAME against this
    exact literal at runtime — it does not derive the prefix from the stack
    name. Dropping it (the redundant aiml-security-aiml-security-<acct>-...
    prefix noted in rebrand-plan.md section 14) would silently disable
    self-exclusion for every sibling assessment Lambda, not just this one.
    That is why Stage 2b renames only the function-name SUFFIX and explicitly
    does not implement the prefix removal recorded as item 8 in the Stage 2b
    design doc.
    """
    app_path = os.path.join(
        REPO_ROOT,
        "aiml-security-assessment",
        "functions",
        "security",
        "finserv_assessments",
        "app.py",
    )
    with open(app_path) as handle:
        source = handle.read()
    assert 'own_name.startswith("aiml-security-")' in source


def test_assessment_bucket_retention_cannot_regress(template, template_multi):
    """Retention is already in force; this guards against silent removal."""
    for parsed in (template, template_multi):
        bucket = parsed["Resources"]["AIMLAssessmentBucket"]
        assert bucket["DeletionPolicy"] == "Retain"
        assert bucket["UpdateReplacePolicy"] == "Retain"


def test_stack_outputs_are_frozen(template):
    outputs = template["Outputs"]
    assert "AIMLAssessmentStateMachineArn" in outputs
    assert "AssessmentBucketName" in outputs


@pytest.mark.parametrize(
    "deployment_template",
    ["aiml-security-single-account.yaml", "2-aiml-security-codebuild.yaml"],
)
def test_legacy_toggle_parameter_is_frozen(deployment_template):
    """EnableFinServAssessment is a customer-supplied CloudFormation parameter,
    retained permanently as a legacy alias for EnableResponsibleAIGRCAssessment
    (the primary parameter).

    It lives in the deployment templates, not in the SAM application template —
    the effective toggle reaches the state machine as the
    ENABLE_RESPONSIBLE_AI_GRC CodeBuild environment variable and then the
    enableResponsibleAIGRC execution input, with ENABLE_FINSERV resolved into
    it upstream in buildspec.yml.
    """
    parsed = _load_template(os.path.join(REPO_ROOT, "deployment", deployment_template))
    assert "EnableFinServAssessment" in parsed["Parameters"]
    assert "EnableResponsibleAIGRCAssessment" in parsed["Parameters"]


SUFFIX = "RAIGRCAssessment"
RETIRED_SUFFIX = "FinServAssessment"

# Every stack-name form buildspec.yml actually produces (see buildspec.yml's
# `sam deploy --stack-name` call sites): single-account, multi-account member
# (which nests the literal "aiml-security-" prefix a second time inside the
# stack name itself, per rebrand-plan.md section 14), and the management
# account. All three must stay under Lambda's 64-character FunctionName limit.
STACK_NAME_FORMS = {
    "single-account": "aiml-sec-123456789012",
    "multi-account-member": "aiml-security-123456789012",
    "management": "aiml-security-mgmt",
}


@pytest.mark.parametrize(
    "stack_name", STACK_NAME_FORMS.values(), ids=STACK_NAME_FORMS.keys()
)
def test_function_name_fits_the_lambda_limit(stack_name):
    rendered = f"aiml-security-{stack_name}-{SUFFIX}"
    assert len(rendered) <= 64, f"{rendered} is {len(rendered)} characters"


def test_retired_suffix_would_have_also_fit_but_new_suffix_is_shorter():
    """Confirms the Stage 2b suffix choice, not just its own budget.

    RAIGRCAssessment (16 chars) is shorter than the retired FinServAssessment
    (17 chars) it replaces, so this is not a regression against the old
    budget even though it is not the tightest possible name.
    """
    assert len(SUFFIX) < len(RETIRED_SUFFIX)


def test_infeasible_full_name_candidates_are_recorded_as_infeasible():
    """rebrand-plan.md section 14's identifier-length budget, asserted.

    ResponsibleAIGRCAssessment and ResponsibleAIGovAssessment both exceed the
    64-character limit for the multi-account member stack form -- this is WHY
    Stage 2b uses the abbreviated RAIGRCAssessment suffix instead.
    """
    worst_case_stack_name = STACK_NAME_FORMS["multi-account-member"]
    for infeasible_suffix in (
        "ResponsibleAIGRCAssessment",
        "ResponsibleAIGovAssessment",
    ):
        rendered = f"aiml-security-{worst_case_stack_name}-{infeasible_suffix}"
        assert len(rendered) > 64, (
            f"{rendered} ({len(rendered)} chars) was expected to exceed the "
            "64-character limit -- if it no longer does, the recorded "
            "identifier-length budget in rebrand-plan.md section 14 is stale."
        )


# ---------------------------------------------------------------------------
# Report DOM: slug, anchor, data attributes, and CSS class names. The visible
# text above these may change; these strings may not.
# ---------------------------------------------------------------------------

SERVICE_SLUG = "finserv"

FROZEN_SELECTORS = [
    'id="finserv"',
    'data-service="finserv"',
    'data-filter-service="finserv"',
    'data-scope-service="finserv"',
    '<option value="finserv">',
    'href="#finserv"',
]

FROZEN_CSS_CLASSES = [
    "industry-item",
    "industry-nav",
    "industry-chip",
    "scope-industry",
    "scope-industry-label",
]


def _render_with_finserv() -> str:
    findings = [
        {
            "account_id": "123456789012",
            "check_id": "FS-01",
            "finding": "Example Responsible AI GRC Finding",
            "details": "Example details.",
            "resolution": "Example resolution.",
            "reference": "https://example.com/doc",
            "severity": "High",
            "status": "Failed",
            "region": "us-east-1",
            "_service": SERVICE_SLUG,
        }
    ]
    return report_template.generate_html_report(
        all_findings=findings,
        service_findings={SERVICE_SLUG: findings},
        service_stats={SERVICE_SLUG: {"passed": 0, "failed": 1, "na": 0}},
        mode="single",
        account_id="123456789012",
        regions=["us-east-1"],
    )


@pytest.fixture(scope="module")
def rendered_html():
    return _render_with_finserv()


@pytest.mark.parametrize("selector", FROZEN_SELECTORS)
def test_report_selectors_are_frozen(rendered_html, selector):
    assert selector in rendered_html


@pytest.mark.parametrize("css_class", FROZEN_CSS_CLASSES)
def test_report_css_classes_are_frozen(rendered_html, css_class):
    assert css_class in rendered_html


# ---------------------------------------------------------------------------
# Phase 2 Stage 2b, item 4: additive Responsible AI GRC selectors ALONGSIDE
# (never replacing) every frozen selector above. Every legacy selector must
# still be present in the exact same rendered output that also carries these.
# ---------------------------------------------------------------------------

ADDITIVE_SELECTORS = [
    'data-service-alias="responsible-ai-grc"',
    'data-scope-service-alias="responsible-ai-grc"',
    'data-service-section-alias="responsible-ai-grc"',
    'id="responsible-ai-grc"',
]


@pytest.mark.parametrize("selector", ADDITIVE_SELECTORS)
def test_additive_responsible_ai_grc_selectors_are_present(rendered_html, selector):
    assert selector in rendered_html


@pytest.mark.parametrize("selector", FROZEN_SELECTORS)
def test_legacy_selectors_still_present_alongside_additive_ones(
    rendered_html, selector
):
    """Redundant with test_report_selectors_are_frozen, run again here to make
    the additive/legacy coexistence explicit as its own regression class: a
    change that adds new selectors by MOVING or REPLACING old ones (rather
    than purely adding) would pass the additive test above while failing this
    one, or vice versa. Both must hold in the same render.
    """
    assert selector in rendered_html


def test_additive_selector_does_not_change_the_service_attribute_value():
    """The client-side filter in report_template.py's applyFilters() matches
    data-service by exact string against <option value="finserv">. Item 4 must
    add a SIBLING attribute, never alter data-service's own value — doing the
    latter would silently break the existing "finserv" filter dropdown entry.
    """
    findings = [
        {
            "account_id": "123456789012",
            "check_id": "FS-01",
            "finding": "Example Responsible AI GRC Finding",
            "details": "Example details.",
            "resolution": "Example resolution.",
            "reference": "https://example.com/doc",
            "severity": "High",
            "status": "Failed",
            "region": "us-east-1",
            "_service": SERVICE_SLUG,
        }
    ]
    html = report_template.generate_html_report(
        all_findings=findings,
        service_findings={SERVICE_SLUG: findings},
        service_stats={SERVICE_SLUG: {"passed": 0, "failed": 1, "na": 0}},
        mode="single",
        account_id="123456789012",
        regions=["us-east-1"],
    )
    assert 'data-service="finserv"' in html
    assert 'data-service="responsible-ai-grc"' not in html
    assert '<option value="responsible-ai-grc">' not in html


def test_service_slug_is_frozen():
    """The display name may change; the slug keyed by the parser may not."""
    assert SERVICE_SLUG == "finserv"
    assert report_template.FINSERV_GUIDE_URL.startswith("https://")


@pytest.mark.parametrize(
    "source_path",
    [
        os.path.join(REPORT_DIR, "app.py"),
        os.path.join(REPO_ROOT, "consolidate_html_reports.py"),
    ],
)
def test_show_finserv_flag_is_frozen(source_path):
    """show_finserv suppresses FS-* rows when the capability ran OWASP-only.

    It is a keyword argument on generate_html_report in the report app and a
    local in the multi-account consolidator. It is NOT in report_template.py.
    """
    with open(source_path) as handle:
        assert "show_finserv" in handle.read()


# ---------------------------------------------------------------------------
# Persisted object names.
# ---------------------------------------------------------------------------


def test_csv_prefix_is_frozen():
    owasp_app_path = os.path.join(
        REPO_ROOT,
        "aiml-security-assessment",
        "functions",
        "security",
        "owasp_assessments",
        "app.py",
    )
    source = open(owasp_app_path).read()
    assert 'FINSERV_SERVICE_CSV_PREFIX = "finserv_security_report"' in source
