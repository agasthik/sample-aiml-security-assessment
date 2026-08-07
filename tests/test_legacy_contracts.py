"""Compatibility locks for report selectors, CSS classes, and deployment identities.

The Responsible AI GRC rebrand changes visible *labels*. It must not change any
selector, CSS class, anchor, slug, logical ID, physical name, state machine
state name, or result path. Archived HTML reports, the report consolidation
tooling, and any customer automation built on the DOM all depend on those.

If a rename makes one of these fail, the rename is wrong — not the test.
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
# Step Functions: all FOUR FinServ state names are customer-visible in the
# console and in execution history.
# ---------------------------------------------------------------------------

ASL_STATE_NAMES = [
    "FinServ Enabled?",
    "FinServ Security Assessment",
    "FinServ Assessment Incomplete",
    "FinServ Assessment Skipped",
]


@pytest.mark.parametrize("state_name", ASL_STATE_NAMES)
def test_asl_state_names_are_frozen(asl, state_name):
    assert f'"{state_name}"' in asl


def test_asl_error_result_path_is_frozen(asl):
    assert '"ResultPath": "$.finservError"' in asl


def test_asl_lambda_substitution_is_frozen(asl):
    assert "${FinServSecurityAssessmentFunction}" in asl


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
# ---------------------------------------------------------------------------

LOGICAL_ID = "FinServSecurityAssessmentFunction"


def test_logical_id_is_frozen(template, template_multi):
    assert LOGICAL_ID in template["Resources"]
    assert LOGICAL_ID in template_multi["Resources"]


def test_physical_function_name_is_frozen(template):
    function_name = template["Resources"][LOGICAL_ID]["Properties"]["FunctionName"]
    assert function_name == {
        "Fn::Sub": "aiml-security-${AWS::StackName}-FinServAssessment"
    }


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
    """EnableFinServAssessment is a customer-supplied CloudFormation parameter.

    It lives in the deployment templates, not in the SAM application template —
    the toggle reaches the state machine as the ENABLE_FINSERV CodeBuild
    environment variable and then the enableFinServ execution input.
    """
    parsed = _load_template(os.path.join(REPO_ROOT, "deployment", deployment_template))
    assert "EnableFinServAssessment" in parsed["Parameters"]


def test_function_name_fits_the_lambda_limit():
    """Worst case is the multi-account member stack: aiml-security-<12-digit>."""
    longest_stack_name = "aiml-security-123456789012"
    rendered = f"aiml-security-{longest_stack_name}-FinServAssessment"
    assert len(rendered) <= 64, f"{rendered} is {len(rendered)} characters"


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
