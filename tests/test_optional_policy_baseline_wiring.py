from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATHS = [
    REPO_ROOT / "aiml-security-assessment" / "template.yaml",
    REPO_ROOT / "aiml-security-assessment" / "template-multi-account.yaml",
]
EXPECTED_ENV_OWNERS = {
    "REQUIRE_BEDROCK_ZERO_DATA_RETENTION": (
        "BedrockSecurityAssessmentFunction",
        "RequireBedrockZeroDataRetention",
    ),
    "REQUIRE_MARKETPLACE_ENDPOINT_CMK": (
        "BedrockSecurityAssessmentFunction",
        "RequireMarketplaceEndpointCMK",
    ),
    "AIML_APPROVED_EXTERNAL_ACCOUNT_IDS": (
        "SagemakerSecurityAssessmentFunction",
        "ApprovedExternalAccountIds",
    ),
    "AIML_APPROVED_ORG_IDS": (
        "SagemakerSecurityAssessmentFunction",
        "ApprovedOrganizationIds",
    ),
    "AGENTCORE_TOKEN_VAULT_ID": (
        "AgentCoreSecurityAssessmentFunction",
        "AgentCoreTokenVaultId",
    ),
    "REQUIRE_AGENTCORE_ONLINE_EVALUATION": (
        "AgentCoreSecurityAssessmentFunction",
        "RequireAgentCoreOnlineEvaluation",
    ),
}


class CfnLoader(yaml.SafeLoader):
    pass


def _construct_intrinsic(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {f"Fn::{tag_suffix}": value}


CfnLoader.add_multi_constructor("!", _construct_intrinsic)


@pytest.mark.parametrize("template_path", TEMPLATE_PATHS, ids=lambda path: path.name)
def test_optional_policy_baselines_are_wired_to_consuming_lambdas(template_path):
    with template_path.open(encoding="utf-8") as template_file:
        template = yaml.load(template_file, Loader=CfnLoader)  # nosec B506

    resources = template["Resources"]
    for variable, (expected_owner, parameter) in EXPECTED_ENV_OWNERS.items():
        owners = []
        for logical_id, resource in resources.items():
            variables = (
                resource.get("Properties", {})
                .get("Environment", {})
                .get("Variables", {})
            )
            if variable in variables:
                owners.append(logical_id)
                assert variables[variable] == {"Fn::Ref": parameter}

        assert owners == [expected_owner], (
            f"{variable} must be configured only on {expected_owner}; found {owners}"
        )
