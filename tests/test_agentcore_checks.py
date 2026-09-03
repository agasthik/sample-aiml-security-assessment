"""
Tests for AgentCore and Agent Registry security assessment checks (AC-01 through AC-23).

AgentCore checks differ from Bedrock/SageMaker:
- Return List[Dict] directly (not a dict with 'csv_data' key)
- Use module-level boto3 clients that must be patched at module level
- Use SeverityEnum/StatusEnum values in create_finding calls

Each check is tested for:
- No resources found -> N/A status
- Compliant resources -> Passed status
- Non-compliant resources -> Failed with correct severity
- Exception handling -> returns error finding (list not empty)
- Output schema validity
"""

import sys
import os
import importlib.util
from unittest.mock import patch, MagicMock

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

sys.path.insert(0, "aiml-security-assessment/functions/security/agentcore_assessments")
from tests.test_helpers import extract_csv_data, assert_finding_schema

# Load agentcore app module directly to avoid name collisions with other app.py files
_ac_dir = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment/functions/security/agentcore_assessments",
    )
)
if _ac_dir not in sys.path:
    sys.path.insert(0, _ac_dir)

_spec = importlib.util.spec_from_file_location(
    "agentcore_app", os.path.join(_ac_dir, "app.py")
)
agentcore_app = importlib.util.module_from_spec(_spec)
sys.modules["agentcore_app"] = agentcore_app
_spec.loader.exec_module(agentcore_app)


# ---------------------------------------------------------------------------
# Helper: patch AgentCore module-level clients
# ---------------------------------------------------------------------------
def _make_client_error(code="ResourceNotFoundException", message="Not found"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "operation")


# ===================================================================
# AC-01: check_agentcore_vpc_configuration
# ===================================================================
class TestAC01VPCConfiguration:
    """AC-01: Check VPC configuration for AgentCore resources."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac01_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_vpc_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-01"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac01_no_runtimes_returns_na(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        result = agentcore_app.check_agentcore_vpc_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac01_runtime_public_returns_failed(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeId": "rt-1", "agentRuntimeName": "TestRT"}]
        }
        mock_ac.get_agent_runtime.return_value = {
            "networkConfiguration": {"networkMode": "PUBLIC"}
        }
        result = agentcore_app.check_agentcore_vpc_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac01_runtime_vpc_configured_returns_passed(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeId": "rt-1", "agentRuntimeName": "TestRT"}]
        }
        mock_ac.get_agent_runtime.return_value = {
            "networkConfiguration": {
                "networkMode": "VPC",
                "subnetIds": ["subnet-123"],
            }
        }
        mock_ec2.describe_subnets.return_value = {
            "Subnets": [{"SubnetId": "subnet-123"}]
        }
        mock_ec2.describe_route_tables.return_value = {
            "RouteTables": [{"Routes": [{"GatewayId": "local"}]}]
        }
        result = agentcore_app.check_agentcore_vpc_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_ac01_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_agent_runtimes.side_effect = Exception("VPC error")
        result = agentcore_app.check_agentcore_vpc_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac01_schema_valid(self):
        result = agentcore_app.check_agentcore_vpc_configuration()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-02: check_agentcore_full_access_roles
# ===================================================================
class TestAC02FullAccessRoles:
    """AC-02: Check for roles with AgentCore full access."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac02_client_unavailable_returns_na(self, empty_permission_cache):
        result = agentcore_app.check_agentcore_full_access_roles(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-02"

    @patch("agentcore_app.agentcore_client")
    def test_ac02_no_full_access_returns_passed(
        self, mock_ac, permission_cache_compliant
    ):
        result = agentcore_app.check_agentcore_full_access_roles(
            permission_cache_compliant
        )
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        # Compliant cache has no AgentCore full access

    @patch("agentcore_app.agentcore_client")
    def test_ac02_full_access_returns_failed(
        self, mock_ac, permission_cache_agentcore_full_access
    ):
        result = agentcore_app.check_agentcore_full_access_roles(
            permission_cache_agentcore_full_access
        )
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        has_failed = any(f["Status"] == "Failed" for f in findings)
        assert has_failed

    def test_ac02_agent_registry_full_access_and_wildcard_return_failed(self):
        permission_cache = {
            "role_permissions": {
                "RegistryAdministrator": {
                    "attached_policies": [{"name": "AgentRegistryFullAccess"}],
                    "inline_policies": [
                        {
                            "name": "RegistryWildcard",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "agent-registry:*",
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert len([f for f in findings if f["Status"] == "Failed"]) == 2
        assert all("Agent Registry" in f["Finding_Details"] for f in findings)

    def test_ac02_detects_wildcard_in_generic_attached_policy_document(self):
        permission_cache = {
            "role_permissions": {
                "RegistryOperator": {
                    "attached_policies": [
                        {
                            "name": "RegistryOps",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "agent-registry:*",
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        wildcard_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore IAM Wildcard Permissions"
        )
        assert wildcard_finding["Status"] == "Failed"
        assert "RegistryOperator" in wildcard_finding["Finding_Details"]

    @pytest.mark.parametrize(
        "action",
        [
            "agent-registry:*",
            "agent-registry:Get*",
            "bedrock-agentcore:*Runtime*",
            "BEDROCK-AGENTCORE:GetAgentRuntim?",
        ],
        ids=["full", "prefix", "embedded", "case-insensitive-question-mark"],
    )
    def test_ac02_detects_agent_platform_wildcard_action_patterns(self, action):
        permission_cache = {
            "role_permissions": {
                "WildcardRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "WildcardPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": action,
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        wildcard_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore IAM Wildcard Permissions"
        )
        assert wildcard_finding["Status"] == "Failed"
        assert "WildcardRole" in wildcard_finding["Finding_Details"]

    @pytest.mark.parametrize(
        "not_action",
        [
            ["bedrock-agentcore:DeleteAgentRuntime"],
            ["bedrock-agentcore:*"],
            ["agent-registry:*", "iam:*"],
        ],
        ids=["partial-agentcore", "agentcore-only", "registry-only"],
    )
    def test_ac02_detects_allow_not_action_that_includes_platform_services(
        self, not_action
    ):
        permission_cache = {
            "role_permissions": {
                "AllowExceptRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "AllowExceptPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": not_action,
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        wildcard_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore IAM Wildcard Permissions"
        )
        assert wildcard_finding["Status"] == "Failed"
        assert "AllowExceptRole" in wildcard_finding["Finding_Details"]
        assert "allow-except" in wildcard_finding["Finding_Details"]

    @pytest.mark.parametrize(
        "not_action",
        [
            ["iam:*", "organizations:*"],
            ["s3:DeleteBucket"],
        ],
        ids=["administrator-except-iam", "administrator-except-one-action"],
    )
    def test_ac02_ignores_not_action_that_names_no_platform_namespace(self, not_action):
        """A NotAction naming no platform namespace is an administrator-style
        grant, which AC-02 ignores exactly as it ignores ``Action: "*"``."""
        permission_cache = {
            "role_permissions": {
                "AllowExceptRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "AllowExceptPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": not_action,
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    @pytest.mark.parametrize(
        "not_action",
        [
            ["bedrock-agentcore:*", "agent-registry:*"],
            ["bedrock-*:*", "agent-registry:*"],
            "*",
            "*:*",
        ],
        ids=["both-namespaces", "service-pattern", "all-actions", "all-services"],
    )
    def test_ac02_ignores_not_action_that_excludes_all_platform_access(
        self, not_action
    ):
        permission_cache = {
            "role_permissions": {
                "ExcludedPlatformRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "ExcludedPlatformPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": not_action,
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    @pytest.mark.parametrize(
        ("action", "resource"),
        [
            ("agent-registry:GetRegistry", "*"),
            ("unrelated-service:Get*", "*"),
            ("bedrock-agentcore-control:*", "*"),
            (
                "bedrock-agentcore:Get*",
                "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/runtime-1",
            ),
        ],
        ids=[
            "exact-action",
            "unrelated-service",
            "invalid-iam-prefix",
            "scoped-resource",
        ],
    )
    def test_ac02_ignores_non_risky_or_unrelated_action_patterns(
        self, action, resource
    ):
        permission_cache = {
            "role_permissions": {
                "ScopedRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "ScopedPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": action,
                                    "Resource": resource,
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    @pytest.mark.parametrize(
        "statements",
        [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
            [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Action": "bedrock-agentcore:*",
                    "Resource": "*",
                },
            ],
        ],
        ids=["administrator-access", "administrator-access-with-platform-deny"],
    )
    def test_ac02_ignores_service_agnostic_wildcard_actions(self, statements):
        permission_cache = {
            "role_permissions": {
                "Administrator": {
                    "attached_policies": [
                        {
                            "name": "AdministratorAccess",
                            "document": {"Statement": statements},
                        }
                    ],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_ac02_empty_cache_returns_findings(self, mock_ac, empty_permission_cache):
        result = agentcore_app.check_agentcore_full_access_roles(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac02_schema_valid(self, mock_ac, empty_permission_cache):
        result = agentcore_app.check_agentcore_full_access_roles(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-03: check_stale_agentcore_access
# ===================================================================
def _agent_platform_policy(name, action):
    return {
        "name": name,
        "arn": f"arn:aws:iam::123456789012:policy/{name}",
        "document": {
            "Statement": {
                "Effect": "Allow",
                "Action": action,
                "Resource": "*",
            }
        },
    }


class TestAC03StaleAccess:
    """AC-03: Check stale AgentCore access."""

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac03_client_unavailable_returns_na(
        self, mock_boto_client, empty_permission_cache
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        result = agentcore_app.check_stale_agentcore_access(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-03"

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac03_empty_cache_returns_findings(
        self, mock_ac, mock_iam, mock_boto_client, empty_permission_cache
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        result = agentcore_app.check_stale_agentcore_access(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac03_schema_valid(
        self, mock_ac, mock_iam, mock_boto_client, empty_permission_cache
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        result = agentcore_app.check_stale_agentcore_access(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_recognizes_agent_registry_permissions_and_access_history(
        self, mock_iam, mock_boto_client, mock_sleep
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {
                    "ServiceName": "AWS Agent Registry",
                    "ServiceNamespace": "agent-registry",
                    "LastAuthenticated": agentcore_app.get_current_utc_date(),
                }
            ],
        }
        permission_cache = {
            "role_permissions": {
                "RegistryReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentRegistryReadOnly",
                            "agent-registry:ListRegistries",
                        )
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert findings[0]["Status"] == "Passed"
        mock_iam.generate_service_last_accessed_details.assert_called_once()

    @pytest.mark.parametrize(
        ("principal_key", "principal_name"),
        [("role_permissions", "RegistryRole"), ("user_permissions", "RegistryUser")],
        ids=["role", "user"],
    )
    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_recognizes_generic_attached_policy_documents(
        self,
        mock_iam,
        mock_boto_client,
        mock_sleep,
        principal_key,
        principal_name,
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {
                    "ServiceName": "AWS Agent Registry",
                    "ServiceNamespace": "agent-registry",
                    "LastAuthenticated": agentcore_app.get_current_utc_date(),
                }
            ],
        }
        permission_cache = {
            "role_permissions": {},
            "user_permissions": {},
        }
        permission_cache[principal_key][principal_name] = {
            "attached_policies": [
                {
                    "name": "RegistryOps",
                    "document": {
                        "Statement": {
                            "Effect": "Allow",
                            "Action": "agent-registry:ListRegistries",
                            "Resource": "*",
                        }
                    },
                }
            ],
            "inline_policies": [],
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert findings[0]["Status"] == "Passed"
        mock_iam.generate_service_last_accessed_details.assert_called_once()

    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_includes_allow_not_action_principal(
        self, mock_iam, mock_boto_client, mock_sleep
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {
                    "ServiceName": "Amazon Bedrock AgentCore",
                    "ServiceNamespace": "bedrock-agentcore",
                    "LastAuthenticated": agentcore_app.get_current_utc_date(),
                }
            ],
        }
        permission_cache = {
            "role_permissions": {
                "AllowExceptRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "AllowExceptPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": ["bedrock-agentcore:StopAgentRuntime"],
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert findings[0]["Status"] == "Passed"
        mock_iam.generate_service_last_accessed_details.assert_called_once()

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_ignores_not_action_that_names_no_platform_namespace(
        self, mock_iam, mock_boto_client
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        permission_cache = {
            "role_permissions": {
                "AllowExceptRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "AllowExceptPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": ["iam:*", "organizations:*"],
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        mock_iam.generate_service_last_accessed_details.assert_not_called()

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_ignores_not_action_excluding_both_platform_namespaces(
        self, mock_iam, mock_boto_client
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        permission_cache = {
            "role_permissions": {
                "ExcludedPlatformRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "ExcludedPlatformPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": [
                                        "bedrock-agentcore:*",
                                        "agent-registry:*",
                                    ],
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        mock_iam.generate_service_last_accessed_details.assert_not_called()

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_ignores_service_agnostic_wildcard_actions(
        self, mock_iam, mock_boto_client
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        permission_cache = {
            "role_permissions": {
                "Administrator": {
                    "attached_policies": [
                        {
                            "name": "AdministratorAccess",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "*",
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert (
            findings[0]["Finding_Details"]
            == "No IAM principals with AgentCore permissions found"
        )
        mock_iam.generate_service_last_accessed_details.assert_not_called()

    @pytest.mark.parametrize(
        ("policy_name", "statement"),
        [
            (
                "DenyAgentRegistryAccess",
                {
                    "Effect": "Deny",
                    "Action": "agent-registry:*",
                    "Resource": "*",
                },
            ),
            (
                "AgentRegistryDocumentationOnly",
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::example-docs/*",
                },
            ),
        ],
        ids=["deny-only", "misleading-name"],
    )
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_attached_policy_names_do_not_imply_access(
        self, mock_iam, mock_boto_client, policy_name, statement
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        permission_cache = {
            "role_permissions": {
                "NoAgentPlatformAccess": {
                    "attached_policies": [
                        {
                            "name": policy_name,
                            "arn": (f"arn:aws:iam::123456789012:policy/{policy_name}"),
                            "document": {"Statement": statement},
                        }
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert (
            findings[0]["Finding_Details"]
            == "No IAM principals with AgentCore permissions found"
        )
        mock_iam.generate_service_last_accessed_details.assert_not_called()

    @patch("agentcore_app.check_timeout", return_value=False)
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_timeout_before_first_principal_returns_incomplete_na(
        self, mock_iam, mock_boto_client, mock_check_timeout
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        permission_cache = {
            "role_permissions": {
                "RuntimeReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                },
                "RegistryReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentRegistryReadOnly",
                            "agent-registry:ListRegistries",
                        )
                    ],
                    "inline_policies": [],
                },
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert "2 IAM principal(s)" in findings[0]["Finding_Details"]
        mock_iam.generate_service_last_accessed_details.assert_not_called()
        mock_check_timeout.assert_called_once()

    @patch("agentcore_app.check_timeout", side_effect=[True, True, False])
    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_timeout_during_polling_stops_before_next_principal(
        self,
        mock_iam,
        mock_boto_client,
        mock_sleep,
        mock_check_timeout,
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        permission_cache = {
            "role_permissions": {
                "RuntimeReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                },
                "RegistryReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentRegistryReadOnly",
                            "agent-registry:ListRegistries",
                        )
                    ],
                    "inline_policies": [],
                },
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert "2 IAM principal(s)" in findings[0]["Finding_Details"]
        mock_iam.generate_service_last_accessed_details.assert_called_once()
        mock_iam.get_service_last_accessed_details.assert_not_called()
        mock_sleep.assert_called_once_with(2)
        assert mock_check_timeout.call_count == 3

    @patch(
        "agentcore_app.check_timeout",
        side_effect=[True, True, True, False],
    )
    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_timeout_preserves_completed_principal_findings(
        self,
        mock_iam,
        mock_boto_client,
        mock_sleep,
        mock_check_timeout,
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {
                    "ServiceName": "Amazon Bedrock AgentCore",
                    "ServiceNamespace": "bedrock-agentcore",
                    "LastAuthenticated": "2020-01-01T00:00:00+00:00",
                }
            ],
        }
        permission_cache = {
            "role_permissions": {
                "StaleRuntimeReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                },
                "RegistryReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentRegistryReadOnly",
                            "agent-registry:ListRegistries",
                        )
                    ],
                    "inline_policies": [],
                },
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert {finding["Status"] for finding in findings} == {"Failed", "N/A"}
        stale_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore Stale Access"
        )
        incomplete_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore Stale Access Check Incomplete"
        )
        assert "StaleRuntimeReader" in stale_finding["Finding_Details"]
        assert "1 IAM principal(s)" in incomplete_finding["Finding_Details"]
        assert incomplete_finding["Severity"] == "Informational"
        mock_iam.generate_service_last_accessed_details.assert_called_once()
        mock_iam.get_service_last_accessed_details.assert_called_once_with(
            JobId="job-1"
        )
        mock_sleep.assert_called_once_with(2)
        assert mock_check_timeout.call_count == 4

    @patch("agentcore_app.check_timeout", return_value=True)
    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_iam_job_timeout_is_informational_na(
        self,
        mock_iam,
        mock_boto_client,
        mock_sleep,
        mock_check_timeout,
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "IN_PROGRESS"
        }
        permission_cache = {
            "role_permissions": {
                "RuntimeReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert "IAM job timed out after 30s" in findings[0]["Finding_Details"]
        assert mock_iam.get_service_last_accessed_details.call_count == 15
        assert mock_sleep.call_count == 15
        assert mock_check_timeout.call_count == 31

    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_uses_most_recent_matching_service_access(
        self, mock_iam, mock_boto_client, mock_sleep
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {
                    "ServiceName": "Amazon Bedrock AgentCore",
                    "ServiceNamespace": "bedrock-agentcore",
                    "LastAuthenticated": "2020-01-01T00:00:00+00:00",
                },
                {
                    "ServiceName": "AWS Agent Registry",
                    "ServiceNamespace": "agent-registry",
                    "LastAuthenticated": agentcore_app.get_current_utc_date(),
                },
            ],
        }
        permission_cache = {
            "role_permissions": {
                "AgentPlatformReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentRegistryReadOnly",
                            "agent-registry:ListRegistries",
                        )
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert findings[0]["Status"] == "Passed"


# ===================================================================
# AC-04: check_agentcore_observability
# ===================================================================
class TestAC04Observability:
    """AC-04: Check AgentCore observability (logging/tracing)."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac04_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_observability()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-04"

    @patch("agentcore_app.cloudwatch_client")
    @patch("agentcore_app.xray_client")
    @patch("agentcore_app.logs_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac04_no_runtimes_returns_na(self, mock_ac, mock_logs, mock_xray, mock_cw):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        result = agentcore_app.check_agentcore_observability()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac04_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_agent_runtimes.side_effect = Exception("Observability error")
        result = agentcore_app.check_agentcore_observability()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac04_schema_valid(self):
        result = agentcore_app.check_agentcore_observability()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-05: check_agentcore_encryption
# ===================================================================
class TestAC05Encryption:
    """AC-05: Check AgentCore ECR encryption."""

    @patch("agentcore_app.ecr_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac05_client_unavailable_returns_na(self, mock_ecr):
        mock_ecr.describe_repositories.return_value = {"repositories": []}
        result = agentcore_app.check_agentcore_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-05"

    @patch("agentcore_app.ecr_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac05_no_runtimes_returns_na(self, mock_ac, mock_ecr):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        result = agentcore_app.check_agentcore_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.ecr_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac05_exception_returns_error_finding(self, mock_ac, mock_ecr):
        # Raise on the ECR call which is the first thing the check does
        mock_ecr.describe_repositories.side_effect = Exception("Encryption error")
        result = agentcore_app.check_agentcore_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.ecr_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac05_schema_valid(self, mock_ecr):
        mock_ecr.describe_repositories.return_value = {"repositories": []}
        result = agentcore_app.check_agentcore_encryption()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-06: check_browser_tool_recording
# ===================================================================
class TestAC06BrowserToolRecording:
    """AC-06: Check custom browser session recording."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac06_client_unavailable_returns_na(self):
        result = agentcore_app.check_browser_tool_recording()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-06"

    @patch("agentcore_app.agentcore_client")
    def test_ac06_no_custom_browsers_returns_na(self, mock_ac):
        mock_ac.list_browsers.return_value = {"browserSummaries": []}

        result = agentcore_app.check_browser_tool_recording()
        findings = extract_csv_data(result)

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AC-06"
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding_Details"] == "No custom AgentCore browsers found"
        mock_ac.list_browsers.assert_called_once_with(type="CUSTOM")

    @patch("agentcore_app.agentcore_client")
    def test_ac06_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_browsers.side_effect = Exception("Browser tool error")
        result = agentcore_app.check_browser_tool_recording()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac06_schema_valid(self):
        result = agentcore_app.check_browser_tool_recording()
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    def test_ac06_all_paths_use_consistent_name_and_reference(self):
        findings = []

        with patch("agentcore_app.agentcore_client", None):
            findings.extend(agentcore_app.check_browser_tool_recording())

        inventories = [
            {
                "items": [],
                "errors": [],
                "list_error": RuntimeError("list failed"),
            },
            {"items": [], "errors": [], "list_error": None},
            {
                "items": [
                    {
                        "summary": {"browserId": "br-1", "name": "browser-1"},
                        "detail": {
                            "recording": {
                                "enabled": True,
                                "s3Location": {"bucket": "recordings"},
                            }
                        },
                    }
                ],
                "errors": [],
                "list_error": None,
            },
            {
                "items": [],
                "errors": [
                    {
                        "summary": {"browserId": "br-2", "name": "browser-2"},
                        "error": RuntimeError("detail failed"),
                    }
                ],
                "list_error": None,
            },
        ]
        with patch("agentcore_app.agentcore_client", MagicMock()):
            for inventory in inventories:
                findings.extend(agentcore_app.check_browser_tool_recording(inventory))

            broken_inventory = MagicMock()
            broken_inventory.get.side_effect = RuntimeError("inventory failed")
            findings.extend(
                agentcore_app.check_browser_tool_recording(broken_inventory)
            )

        assert findings
        assert {finding["Finding"] for finding in findings} == {
            "AgentCore Browser Session Recording"
        }
        assert {finding["Reference"] for finding in findings} == {
            agentcore_app.AGENTCORE_SECURITY_HUB_REFERENCE_URL
        }


# ===================================================================
# AC-07: check_agentcore_memory_configuration
# ===================================================================
class TestAC07MemoryConfiguration:
    """AC-07: Check memory resource encryption."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac07_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_memory_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-07"

    @patch("agentcore_app.agentcore_client")
    def test_ac07_no_memories_returns_na(self, mock_ac):
        mock_ac.list_memories.return_value = {"memories": []}
        result = agentcore_app.check_agentcore_memory_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac07_memory_with_wrapped_kms_key_returns_passed(self, mock_ac):
        mock_ac.list_memories.return_value = {
            "memories": [{"id": "mem-123456789012", "name": "TestMemory"}]
        }
        mock_ac.get_memory.return_value = {
            "memory": {
                "id": "mem-123456789012",
                "encryptionKeyArn": "arn:aws:kms:us-east-1:123:key/abc",
            }
        }
        result = agentcore_app.check_agentcore_memory_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_ac07_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_memories.side_effect = Exception("Memory error")
        result = agentcore_app.check_agentcore_memory_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac07_schema_valid(self):
        result = agentcore_app.check_agentcore_memory_configuration()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-08: check_agentcore_vpc_endpoints
# ===================================================================
class TestAC08VPCEndpoints:
    """AC-08: Check VPC endpoints for AgentCore."""

    @patch("agentcore_app.agentcore_client")
    def test_agentcore_list_all_stops_on_repeated_token(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeId": "runtime-1"}],
            "nextToken": "repeated",
        }

        runtimes = agentcore_app._agentcore_list_all(
            "list_agent_runtimes", ["agentRuntimes"]
        )

        assert runtimes == [
            {"agentRuntimeId": "runtime-1"},
            {"agentRuntimeId": "runtime-1"},
        ]
        assert mock_ac.list_agent_runtimes.call_count == 2

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac08_client_unavailable_returns_na(self, mock_ec2):
        mock_ec2.describe_vpcs.return_value = {"Vpcs": []}
        result = agentcore_app.check_agentcore_vpc_endpoints()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-08"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac08_no_runtimes_returns_na(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        result = agentcore_app.check_agentcore_vpc_endpoints()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding_Details"] == "No AgentCore resources found"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac08_reads_runtimes_from_all_pages(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.side_effect = [
            {"agentRuntimes": [], "nextToken": "runtime-page-2"},
            {
                "agentRuntimes": [
                    {
                        "agentRuntimeId": "runtime-2",
                        "agentRuntimeName": "SecondPageRuntime",
                    }
                ]
            },
        ]
        mock_ec2.describe_vpcs.return_value = {"Vpcs": []}

        findings = extract_csv_data(agentcore_app.check_agentcore_vpc_endpoints())

        assert findings[0]["Finding_Details"] == "No VPCs found in the account"
        assert mock_ac.list_agent_runtimes.call_count == 2
        mock_ac.list_agent_runtimes.assert_any_call(nextToken="runtime-page-2")

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac08_exception_returns_error_finding(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [
                {
                    "agentRuntimeId": "runtime-1",
                    "agentRuntimeName": "TestRuntime",
                }
            ]
        }
        mock_ec2.describe_vpcs.side_effect = Exception("VPC endpoint error")
        result = agentcore_app.check_agentcore_vpc_endpoints()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac08_schema_valid(self, mock_ec2):
        mock_ec2.describe_vpcs.return_value = {"Vpcs": []}
        result = agentcore_app.check_agentcore_vpc_endpoints()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-09: check_agentcore_service_linked_role
# ===================================================================
class TestAC09ServiceLinkedRole:
    """AC-09: Check AgentCore service-linked role."""

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac09_client_unavailable_returns_na(self, mock_iam):
        mock_iam.get_role.side_effect = _make_client_error(
            "NoSuchEntity", "Role not found"
        )
        mock_iam.exceptions.NoSuchEntityException = ClientError
        result = agentcore_app.check_agentcore_service_linked_role()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-09"

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac09_slr_exists_returns_passed(self, mock_ac, mock_iam):
        mock_iam.get_role.return_value = {
            "Role": {
                "RoleName": "AWSServiceRoleForBedrockAgentCoreNetwork",
                "Arn": "arn:aws:iam::123:role/aws-service-role/network.bedrock-agentcore.amazonaws.com/AWSServiceRoleForBedrockAgentCoreNetwork",
                "Path": "/aws-service-role/network.bedrock-agentcore.amazonaws.com/",
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "network.bedrock-agentcore.amazonaws.com"
                            },
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
            }
        }
        result = agentcore_app.check_agentcore_service_linked_role()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac09_slr_missing_returns_failed(self, mock_ac, mock_iam):
        mock_iam.get_role.side_effect = _make_client_error(
            "NoSuchEntity", "Role not found"
        )
        result = agentcore_app.check_agentcore_service_linked_role()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_ac09_exception_returns_error_finding(self, mock_ac):
        # Patch iam_client to raise
        with patch("agentcore_app.iam_client") as mock_iam:
            mock_iam.get_role.side_effect = Exception("IAM error")
            result = agentcore_app.check_agentcore_service_linked_role()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac09_schema_valid(self, mock_iam):
        mock_iam.get_role.side_effect = _make_client_error(
            "NoSuchEntity", "Role not found"
        )
        mock_iam.exceptions.NoSuchEntityException = ClientError
        result = agentcore_app.check_agentcore_service_linked_role()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-10: check_agentcore_resource_based_policies
# ===================================================================
class TestAC10ResourceBasedPolicies:
    """AC-10: Check resource-based policies."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac10_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-10"

    @patch("agentcore_app.agentcore_client")
    def test_ac10_no_runtimes_returns_na(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        mock_ac.list_gateways.return_value = {"items": []}
        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac10_uses_generic_resource_policy_api(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [
                {
                    "agentRuntimeId": "rt-1",
                    "agentRuntimeName": "TestRuntime",
                    "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1",
                }
            ]
        }
        mock_ac.list_gateways.return_value = {"items": []}
        mock_ac.get_resource_policy.return_value = {
            "policy": '{"Version":"2012-10-17"}'
        }

        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)

        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        mock_ac.get_resource_policy.assert_called_once_with(
            resourceArn="arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1"
        )

    @patch("agentcore_app.agentcore_client")
    def test_ac10_gets_gateway_by_gateway_identifier(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-1"
        }
        mock_ac.get_resource_policy.return_value = {
            "policy": '{"Version":"2012-10-17"}'
        }

        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)

        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        mock_ac.get_gateway.assert_called_once_with(gatewayIdentifier="gw-1")
        mock_ac.get_resource_policy.assert_called_once_with(
            resourceArn="arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-1"
        )

    @patch("agentcore_app.agentcore_client")
    def test_ac10_access_denied_policy_read_returns_na_finding(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [
                {
                    "agentRuntimeId": "rt-1",
                    "agentRuntimeName": "TestRuntime",
                    "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1",
                }
            ]
        }
        mock_ac.list_gateways.return_value = {"items": []}
        mock_ac.get_resource_policy.side_effect = _make_client_error(
            "AccessDeniedException", "Denied"
        )

        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)

        assert len(findings) >= 1
        assert any(
            f["Finding"] == "AgentCore Resource-Based Policy Assessment Access Denied"
            and f["Status"] == "N/A"
            for f in findings
        )

    @patch("agentcore_app.agentcore_client")
    def test_ac10_policy_read_throttling_returns_incomplete_finding(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [
                {
                    "agentRuntimeId": "rt-1",
                    "agentRuntimeName": "TestRuntime",
                    "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1",
                }
            ]
        }
        mock_ac.list_gateways.return_value = {"items": []}
        mock_ac.get_resource_policy.side_effect = _make_client_error(
            "ThrottlingException", "Try again"
        )

        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)

        assert len(findings) >= 1
        assert any(
            f["Finding"] == "AgentCore Resource-Based Policy Assessment Incomplete"
            and f["Status"] == "N/A"
            for f in findings
        )

    @patch("agentcore_app.agentcore_client")
    def test_ac10_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_agent_runtimes.side_effect = Exception("RBP error")
        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac10_schema_valid(self):
        result = agentcore_app.check_agentcore_resource_based_policies()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-11: check_agentcore_policy_engine_encryption
# ===================================================================
class TestAC11PolicyEngineEncryption:
    """AC-11: Check policy engine encryption."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac11_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_policy_engine_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-11"

    @patch("agentcore_app.agentcore_client")
    def test_ac11_no_policy_engines_returns_na(self, mock_ac):
        mock_ac.list_policy_engines.return_value = {"policyEngines": []}
        result = agentcore_app.check_agentcore_policy_engine_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac11_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_policy_engines.side_effect = Exception("Policy engine error")
        result = agentcore_app.check_agentcore_policy_engine_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac11_schema_valid(self):
        result = agentcore_app.check_agentcore_policy_engine_encryption()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-12: check_agentcore_gateway_encryption
# ===================================================================
class TestAC12GatewayEncryption:
    """AC-12: Check gateway encryption."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac12_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_gateway_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-12"

    @patch("agentcore_app.agentcore_client")
    def test_ac12_no_gateways_returns_na(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": []}
        result = agentcore_app.check_agentcore_gateway_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac12_gateway_with_kms_key_returns_passed(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "kmsKeyArn": "arn:aws:kms:us-east-1:123:key/abc",
        }
        result = agentcore_app.check_agentcore_gateway_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        mock_ac.get_gateway.assert_called_once_with(gatewayIdentifier="gw-1")

    @patch("agentcore_app.agentcore_client")
    def test_ac12_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_gateways.side_effect = Exception("Gateway encryption error")
        result = agentcore_app.check_agentcore_gateway_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac12_schema_valid(self):
        result = agentcore_app.check_agentcore_gateway_encryption()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-13: check_agentcore_gateway_configuration
# ===================================================================
class TestAC13GatewayConfiguration:
    """AC-13: Check gateway configuration."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac13_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_gateway_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-13"

    @patch("agentcore_app.agentcore_client")
    def test_ac13_no_gateways_returns_na(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": []}
        result = agentcore_app.check_agentcore_gateway_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac13_items_gateway_shape_returns_passed(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        result = agentcore_app.check_agentcore_gateway_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_ac13_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_gateways.side_effect = Exception("Gateway config error")
        result = agentcore_app.check_agentcore_gateway_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac13_schema_valid(self):
        result = agentcore_app.check_agentcore_gateway_configuration()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AG-24..AG-27: check_agentcore_gateway_agentic_security
# ===================================================================
class TestAgenticGatewaySecurity:
    """Agentic AI Gateway security checks."""

    @patch("agentcore_app.agentcore_client")
    def test_gateway_policy_controls_fail_when_not_enforced(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "authorizerType": "NONE",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/TestEngine-abcdefghij",
                "mode": "LOG_ONLY",
            },
            "exceptionLevel": "DEBUG",
        }

        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        statuses = {f["Check_ID"]: f["Status"] for f in findings}

        assert statuses["AG-24"] == "Failed"
        assert statuses["AG-25"] == "Failed"
        assert statuses["AG-26"] == "Failed"
        assert statuses["AG-27"] == "Failed"
        for finding in findings:
            assert_finding_schema(finding)

    @patch("agentcore_app.agentcore_client")
    def test_gateway_authorizer_unspecified_fails_closed(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/TestEngine-abcdefghij",
                "mode": "ENFORCE",
            },
            "webAclArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test/abc",
        }
        mock_ac.list_policies.return_value = {
            "policies": [
                {
                    "policyId": "p-1",
                    "status": "ACTIVE",
                    "enforcementMode": "ACTIVE",
                }
            ]
        }
        mock_ac.list_policies.return_value = {
            "policies": [
                {
                    "policyId": "p-1",
                    "status": "ACTIVE",
                    "enforcementMode": "ACTIVE",
                }
            ]
        }

        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        ag24 = [f for f in findings if f["Check_ID"] == "AG-24"]

        assert ag24
        assert ag24[0]["Status"] == "Failed"
        assert "unspecified" in ag24[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_gateway_authenticate_only_without_enforced_policy_fails_closed(
        self, mock_ac
    ):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "authorizerType": "AUTHENTICATE_ONLY",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/TestEngine-abcdefghij",
                "mode": "LOG_ONLY",
            },
            "webAclArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test/abc",
        }
        mock_ac.list_policies.return_value = {
            "policies": [
                {
                    "policyId": "p-1",
                    "status": "ACTIVE",
                    "enforcementMode": "ACTIVE",
                }
            ]
        }

        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        ag24 = [f for f in findings if f["Check_ID"] == "AG-24"]

        assert ag24
        assert ag24[0]["Status"] == "Failed"
        assert "AUTHENTICATE_ONLY" in ag24[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_gateway_authenticate_only_with_enforced_policy_passes(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "authorizerType": "AUTHENTICATE_ONLY",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/TestEngine-abcdefghij",
                "mode": "ENFORCE",
            },
            "webAclArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test/abc",
        }

        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        ag24 = [f for f in findings if f["Check_ID"] == "AG-24"]

        assert ag24
        assert ag24[0]["Status"] == "Passed"
        assert "policy engine" in ag24[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_gateway_detail_access_denied_returns_na(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.side_effect = _make_client_error(
            "AccessDeniedException", "Denied"
        )

        findings = agentcore_app.check_agentcore_gateway_agentic_security()

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AG-24"
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert "Unable to retrieve Gateway" in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.agentcore_client")
    def test_gateway_policy_controls_pass_when_enforced(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "authorizerType": "AWS_IAM",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/TestEngine-abcdefghij",
                "mode": "ENFORCE",
            },
            "webAclArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test/abc",
        }
        mock_ac.list_policies.return_value = {
            "policies": [
                {
                    "policyId": "p-1",
                    "status": "ACTIVE",
                    "enforcementMode": "ACTIVE",
                }
            ]
        }

        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        statuses = {f["Check_ID"]: f["Status"] for f in findings}

        assert statuses["AG-24"] == "Passed"
        assert statuses["AG-25"] == "Passed"
        assert statuses["AG-26"] == "Passed"
        assert statuses["AG-27"] == "Passed"


class TestAgenticAgentCoreMapping:
    """Agentic AI AG-* rows are generated from API-backed AgentCore checks."""

    EXPECTED_AGENTIC_MAPPINGS = {
        "AC-01": "AG-15",
        "AC-02": "AG-16",
        "AC-03": "AG-17",
        "AC-04": "AG-18",
        "AC-07": "AG-19",
        "AC-08": "AG-20",
        "AC-10": "AG-21",
        "AC-11": "AG-22",
        "AC-12": "AG-23",
        "AC-14": "AG-28",
        "AC-15": "AG-29",
        "AC-16": "AG-31",
        "AC-17": "AG-32",
        "AC-18": "AG-33",
        "AC-19": "AG-34",
        "AC-20": "AG-35",
        "AC-21": "AG-36",
        "AC-22": "AG-37",
        "AC-23": "AG-38",
    }

    def test_all_agentcore_agentic_mappings_emit_expected_rows(self):
        source_findings = []
        for source_check_id in self.EXPECTED_AGENTIC_MAPPINGS:
            source_findings.append(
                {
                    "Account_ID": "123456789012",
                    "Check_ID": source_check_id,
                    "Finding": f"{source_check_id} source finding",
                    "Finding_Details": f"{source_check_id} source details",
                    "Resolution": "No action required.",
                    "Reference": "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security.html",
                    "Severity": "Medium",
                    "Status": "Passed",
                    "Region": "us-east-1",
                }
            )

        findings = agentcore_app.build_agentic_agentcore_security_findings(
            source_findings
        )

        assert len(findings) == len(self.EXPECTED_AGENTIC_MAPPINGS)
        actual_by_source = {}
        for finding in findings:
            details = finding["Finding_Details"]
            source_check_id = details.split("Source check ", 1)[1].split(":", 1)[0]
            actual_by_source[source_check_id] = finding

            assert finding["Status"] == "Passed"
            assert finding["Severity"] == "Medium"
            assert finding["Region"] == "us-east-1"
            assert f"Source check {source_check_id}" in details
            assert_finding_schema(finding)

        assert set(actual_by_source) == set(self.EXPECTED_AGENTIC_MAPPINGS)
        for source_check_id, expected_ag_id in self.EXPECTED_AGENTIC_MAPPINGS.items():
            assert actual_by_source[source_check_id]["Check_ID"] == expected_ag_id


class TestProposedAgentCoreChecks:
    """AC-14 through AC-17 and the AC-06 correction."""

    @patch("agentcore_app.agentcore_client")
    def test_ac14_customer_managed_token_vault_passes(self, mock_ac):
        mock_ac.get_token_vault.return_value = {
            "tokenVaultId": "default",
            "kmsConfiguration": {
                "keyType": "CustomerManagedKey",
                "kmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-1",
            },
        }
        finding = agentcore_app.check_agentcore_token_vault_encryption()[0]
        assert finding["Check_ID"] == "AC-14"
        assert finding["Status"] == "Passed"

    @patch.dict(
        os.environ,
        {"AGENTCORE_TOKEN_VAULT_ID": "team-security-vault"},
        clear=False,
    )
    @patch("agentcore_app.agentcore_client")
    def test_ac14_uses_configured_non_default_token_vault(self, mock_ac):
        mock_ac.get_token_vault.return_value = {
            "tokenVaultId": "team-security-vault",
            "kmsConfiguration": {
                "keyType": "CustomerManagedKey",
                "kmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-2",
            },
        }

        finding = agentcore_app.check_agentcore_token_vault_encryption()[0]

        mock_ac.get_token_vault.assert_called_once_with(
            tokenVaultId="team-security-vault"
        )
        assert finding["Status"] == "Passed"
        assert "team-security-vault" in finding["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_ac14_service_managed_token_vault_fails(self, mock_ac):
        mock_ac.get_token_vault.return_value = {
            "tokenVaultId": "default",
            "kmsConfiguration": {"keyType": "ServiceManagedKey"},
        }
        finding = agentcore_app.check_agentcore_token_vault_encryption()[0]
        assert finding["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_ac15_custom_interpreter_vpc_passes(self, mock_ac):
        mock_ac.list_code_interpreters.return_value = {
            "codeInterpreterSummaries": [
                {"codeInterpreterId": "ci-1", "name": "interpreter-1"}
            ]
        }
        mock_ac.get_code_interpreter.return_value = {
            "networkConfiguration": {
                "networkMode": "VPC",
                "vpcConfig": {
                    "subnets": ["subnet-1"],
                    "securityGroups": ["sg-1"],
                },
            }
        }
        finding = agentcore_app.check_agentcore_code_interpreter_isolation()[0]
        assert finding["Check_ID"] == "AC-15"
        assert finding["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_ac15_public_interpreter_fails(self, mock_ac):
        mock_ac.list_code_interpreters.return_value = {
            "codeInterpreterSummaries": [
                {"codeInterpreterId": "ci-1", "name": "interpreter-1"}
            ]
        }
        mock_ac.get_code_interpreter.return_value = {
            "networkConfiguration": {"networkMode": "PUBLIC"}
        }
        finding = agentcore_app.check_agentcore_code_interpreter_isolation()[0]
        assert finding["Status"] == "Failed"

    def test_ac06_and_ac16_share_browser_inventory(self):
        inventory = {
            "items": [
                {
                    "summary": {"browserId": "br-1", "name": "browser-1"},
                    "detail": {
                        "networkConfiguration": {
                            "networkMode": "VPC",
                            "vpcConfig": {
                                "subnets": ["subnet-1"],
                                "securityGroups": ["sg-1"],
                            },
                        },
                        "recording": {
                            "enabled": True,
                            "s3Location": {"bucket": "recordings"},
                        },
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }
        with patch("agentcore_app.agentcore_client", MagicMock()):
            ac06 = agentcore_app.check_browser_tool_recording(inventory)[0]
            ac16 = agentcore_app.check_agentcore_browser_network_isolation(inventory)[0]
        assert ac06["Status"] == "Passed"
        assert ac16["Status"] == "Passed"

    def test_ac16_public_browser_fails(self):
        inventory = {
            "items": [
                {
                    "summary": {"browserId": "br-1", "name": "browser-1"},
                    "detail": {
                        "networkConfiguration": {"networkMode": "PUBLIC"},
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }
        with patch("agentcore_app.agentcore_client", MagicMock()):
            finding = agentcore_app.check_agentcore_browser_network_isolation(
                inventory
            )[0]
        assert finding["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_ac17_operational_evaluation_passes_advisory(self, mock_ac):
        mock_ac.list_online_evaluation_configs.return_value = {
            "onlineEvaluationConfigs": [
                {
                    "onlineEvaluationConfigId": "eval-1",
                    "onlineEvaluationConfigName": "evaluation-1",
                }
            ]
        }
        mock_ac.get_online_evaluation_config.return_value = {
            "status": "ACTIVE",
            "executionStatus": "ENABLED",
            "rule": {"samplingConfig": {"samplingPercentage": 10}},
            "evaluators": [{"evaluatorId": "evaluator-1"}],
            "dataSourceConfig": {
                "cloudWatchLogs": {"logGroupNames": ["/aws/agentcore/input"]}
            },
            "outputConfig": {
                "cloudWatchConfig": {"logGroupName": "/aws/agentcore/output"}
            },
        }
        finding = agentcore_app.check_agentcore_online_evaluation_coverage()[0]
        assert finding["Check_ID"] == "AC-17"
        assert finding["Status"] == "Passed"
        assert finding["Severity"] == "Informational"

    @patch.dict(
        os.environ,
        {"REQUIRE_AGENTCORE_ONLINE_EVALUATION": "false"},
        clear=False,
    )
    @patch("agentcore_app.agentcore_client")
    def test_ac17_incomplete_advisory_evaluation_returns_na(self, mock_ac):
        mock_ac.list_online_evaluation_configs.return_value = {
            "onlineEvaluationConfigs": [
                {
                    "onlineEvaluationConfigId": "eval-1",
                    "onlineEvaluationConfigName": "evaluation-1",
                }
            ]
        }
        mock_ac.get_online_evaluation_config.return_value = {
            "status": "ACTIVE",
            "executionStatus": "DISABLED",
        }

        finding = agentcore_app.check_agentcore_online_evaluation_coverage()[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert finding["Resolution"].startswith("Set the evaluation ACTIVE")

    @patch.dict(
        os.environ,
        {"REQUIRE_AGENTCORE_ONLINE_EVALUATION": "true"},
        clear=False,
    )
    @patch("agentcore_app.agentcore_client")
    def test_ac17_incomplete_required_evaluation_fails(self, mock_ac):
        mock_ac.list_online_evaluation_configs.return_value = {
            "onlineEvaluationConfigs": [
                {
                    "onlineEvaluationConfigId": "eval-1",
                    "onlineEvaluationConfigName": "evaluation-1",
                }
            ]
        }
        mock_ac.get_online_evaluation_config.return_value = {
            "status": "ACTIVE",
            "executionStatus": "DISABLED",
        }
        finding = agentcore_app.check_agentcore_online_evaluation_coverage()[0]
        assert finding["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_new_agentcore_checks_access_denied_return_na(self, mock_ac):
        error = _make_client_error("AccessDeniedException", "Denied")

        mock_ac.get_token_vault.side_effect = error
        ac14 = agentcore_app.check_agentcore_token_vault_encryption()[0]

        mock_ac.reset_mock()
        mock_ac.list_code_interpreters.side_effect = error
        ac15 = agentcore_app.check_agentcore_code_interpreter_isolation()[0]

        mock_ac.reset_mock()
        ac16 = agentcore_app.check_agentcore_browser_network_isolation(
            {"items": [], "errors": [], "list_error": error}
        )[0]

        mock_ac.reset_mock()
        mock_ac.list_online_evaluation_configs.side_effect = error
        ac17 = agentcore_app.check_agentcore_online_evaluation_coverage()[0]

        for finding in (ac14, ac15, ac16, ac17):
            assert finding["Status"] == "N/A"
            assert finding["Severity"] == "Informational"

    @patch("agentcore_app.agentcore_client")
    def test_ag25_fails_when_engine_has_only_log_only_policy(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "gateway-1"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "gateway-1",
            "authorizerType": "AWS_IAM",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/pe-1",
                "mode": "ENFORCE",
            },
        }
        mock_ac.list_policies.return_value = {
            "policies": [
                {
                    "policyId": "p-1",
                    "status": "ACTIVE",
                    "enforcementMode": "LOG_ONLY",
                }
            ]
        }
        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        ag25 = [finding for finding in findings if finding["Check_ID"] == "AG-25"]
        assert ag25[0]["Status"] == "Failed"

    def test_new_agentcore_operation_contracts_exist(self):
        client = agentcore_app.boto3.client(
            "bedrock-agentcore-control",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        )
        model = client.meta.service_model
        for operation in [
            "GetTokenVault",
            "ListCodeInterpreters",
            "GetCodeInterpreter",
            "ListBrowsers",
            "GetBrowser",
            "ListOnlineEvaluationConfigs",
            "GetOnlineEvaluationConfig",
            "ListPolicies",
        ]:
            assert model.operation_model(operation)


# ===================================================================
# AC-18 through AC-23: AWS Agent Registry
# ===================================================================
# Sentinel distinguishing "the service omitted this optional field" from
# "the service returned it empty", which AC-18 grades differently.
_OMITTED = object()


def _registry_item(
    *,
    registry_id="reg-1",
    status="READY",
    approval_configuration=None,
    discovery_configuration=None,
    encryption_configuration=None,
    auto_detection=None,
):
    summary = {
        "registryId": registry_id,
        "name": f"registry-{registry_id}",
        "status": status,
    }
    detail = dict(summary)
    if approval_configuration is not _OMITTED:
        detail["approvalConfiguration"] = approval_configuration or {}
    detail["discoveryConfiguration"] = discovery_configuration or {
        "authorizerType": "AWS_IAM"
    }
    if encryption_configuration is not None:
        detail["encryptionConfiguration"] = encryption_configuration
    if auto_detection is not None:
        detail["autoDetection"] = auto_detection
    return {"summary": summary, "detail": detail}


def _record_item(
    *,
    registry_item=None,
    record_id="record-1",
    status="APPROVED",
    created_by="123456789012",
    created_by_auto_detection=False,
    provenance=None,
):
    registry = registry_item or _registry_item()
    summary = {
        "recordId": record_id,
        "name": f"record-{record_id}",
        "displayName": f"Record {record_id}",
        "status": status,
    }
    if created_by is not None:
        summary["createdBy"] = created_by
    if created_by_auto_detection is not None:
        summary["createdByAutoDetection"] = created_by_auto_detection
    if provenance is not None:
        summary["provenanceSummaryList"] = provenance
    # ``get_agent_registry_record_inventory`` stores the ListRegistryRecords
    # summary as both the summary and the detail, so mirror that exact shape
    # instead of inventing keys the production inventory never produces.
    return {"registry": registry, "summary": summary, "detail": summary}


def _record_inventory(*items, registry_inventory=None):
    parent = registry_inventory or {
        "items": [_registry_item()],
        "errors": [],
        "list_error": None,
        "unavailable": False,
    }
    return {
        "items": list(items),
        "errors": [],
        "list_errors": [],
        "skipped_registries": [],
        "registry_inventory": parent,
    }


class TestAgentRegistryChecks:
    """AC-18 through AC-23 use shared paginated registry inventories."""

    @patch("agentcore_app.agent_registry_control_client")
    def test_registry_inventory_reads_all_pages_and_isolates_detail_errors(
        self, mock_registry
    ):
        paginator = mock_registry.get_paginator.return_value
        paginator.paginate.return_value = [
            {
                "registries": [
                    {"registryId": "reg-1", "name": "registry-1", "status": "READY"}
                ]
            },
            {
                "registries": [
                    {"registryId": "reg-2", "name": "registry-2", "status": "READY"}
                ]
            },
        ]
        mock_registry.get_registry.side_effect = [
            {
                "registryId": "reg-1",
                "name": "registry-1",
                "status": "READY",
                "approvalConfiguration": {},
                "discoveryConfiguration": {"authorizerType": "AWS_IAM"},
            },
            _make_client_error("AccessDeniedException", "Denied"),
        ]

        inventory = agentcore_app.get_agent_registry_inventory()

        assert len(inventory["items"]) == 1
        assert len(inventory["errors"]) == 1
        assert inventory["list_error"] is None
        mock_registry.get_paginator.assert_called_once_with("list_registries")
        assert mock_registry.get_registry.call_count == 2

    @patch("agentcore_app.agent_registry_control_client")
    def test_registry_inventory_list_access_denied_is_indeterminate(
        self, mock_registry
    ):
        mock_registry.get_paginator.return_value.paginate.side_effect = (
            _make_client_error("AccessDeniedException", "Denied")
        )

        inventory = agentcore_app.get_agent_registry_inventory()

        assert inventory["items"] == []
        assert inventory["list_error"] is not None
        assert inventory["unavailable"] is False

    @patch("agentcore_app.agent_registry_control_client", None)
    def test_registry_client_initialization_error_is_indeterminate(self):
        initialization_error = RuntimeError("SDK model could not initialize")

        inventory = agentcore_app.get_agent_registry_inventory(initialization_error)
        finding = agentcore_app.check_agent_registry_approval_governance(inventory)[0]

        assert inventory["unavailable"] is False
        assert inventory["list_error"] is initialization_error
        assert inventory["initialization_error"] is initialization_error
        assert finding["Status"] == "N/A"
        assert (
            "client initialization returned RuntimeError" in finding["Finding_Details"]
        )
        assert "not available in this region" not in finding["Finding_Details"]
        assert "Grant " not in finding["Resolution"]

    @pytest.mark.parametrize(
        "error",
        [
            _make_client_error("ExpiredToken", "Token expired"),
            _make_client_error("SignatureDoesNotMatch", "Bad signature"),
        ],
        ids=["expired-token", "bad-signature"],
    )
    @patch("agentcore_app.agent_registry_control_client")
    def test_registry_inventory_does_not_treat_credential_defects_as_unavailable(
        self, mock_registry, error
    ):
        mock_registry.get_paginator.return_value.paginate.side_effect = error

        inventory = agentcore_app.get_agent_registry_inventory()

        assert inventory["unavailable"] is False
        assert inventory["list_error"] is error

    @pytest.mark.parametrize(
        "error",
        [
            EndpointConnectionError(endpoint_url="https://agent-registry.invalid"),
            _make_client_error("InvalidClientTokenId", "Invalid credentials"),
            _make_client_error("AuthFailure", "Authentication failed"),
            _make_client_error(
                "UnrecognizedClientException", "Unrecognized credentials"
            ),
        ],
        ids=[
            "endpoint",
            "invalid-token",
            "auth-failure",
            "unrecognized-client",
        ],
    )
    @patch("agentcore_app.agent_registry_control_client")
    def test_registry_inventory_treats_disabled_region_signals_as_unavailable(
        self, mock_registry, error
    ):
        mock_registry.get_paginator.return_value.paginate.side_effect = error

        inventory = agentcore_app.get_agent_registry_inventory()

        assert inventory["unavailable"] is True
        assert inventory["list_error"] is error

    @pytest.mark.parametrize(
        "error",
        [
            EndpointConnectionError(endpoint_url="https://agent-registry.invalid"),
            _make_client_error(
                "UnrecognizedClientException", "Unrecognized credentials"
            ),
        ],
        ids=["endpoint", "unrecognized-client"],
    )
    @patch("agentcore_app.agent_registry_control_client")
    def test_registry_check_reports_disabled_region_without_network_remediation(
        self, mock_registry, error
    ):
        mock_registry.get_paginator.return_value.paginate.side_effect = error

        inventory = agentcore_app.get_agent_registry_inventory()
        finding = agentcore_app.check_agent_registry_approval_governance(inventory)[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "not available in this region" in finding["Finding_Details"]
        assert "DNS resolution" not in finding["Resolution"]
        assert "credentials" not in finding["Resolution"]

    @patch("agentcore_app.agent_registry_control_client")
    def test_registry_inventory_marks_opt_in_required_as_unavailable(
        self, mock_registry
    ):
        error = _make_client_error("OptInRequired", "Region is not enabled")
        mock_registry.get_paginator.return_value.paginate.side_effect = error

        inventory = agentcore_app.get_agent_registry_inventory()

        assert inventory["unavailable"] is True
        assert inventory["list_error"] is error

    @patch("agentcore_app.agent_registry_control_client")
    def test_registry_record_inventory_reads_all_pages_without_detail_calls(
        self, mock_registry
    ):
        registry_inventory = {
            "items": [_registry_item()],
            "errors": [],
            "list_error": None,
            "unavailable": False,
        }
        paginator = mock_registry.get_paginator.return_value
        paginator.paginate.return_value = [
            {
                "registryRecords": [
                    {
                        "recordId": "record-1",
                        "name": "record-1",
                        "status": "APPROVED",
                        "createdBy": "123456789012",
                        "createdByAutoDetection": False,
                    }
                ]
            },
            {
                "registryRecords": [
                    {
                        "recordId": "record-2",
                        "name": "record-2",
                        "status": "DRAFT",
                        "createdBy": "111122223333",
                        "createdByAutoDetection": False,
                    }
                ]
            },
        ]

        inventory = agentcore_app.get_agent_registry_record_inventory(
            registry_inventory
        )

        assert len(inventory["items"]) == 2
        assert inventory["errors"] == []
        assert inventory["list_errors"] == []
        mock_registry.get_paginator.assert_called_once_with("list_registry_records")
        paginator.paginate.assert_called_once_with(
            registryId="reg-1",
            PaginationConfig={"MaxItems": 1000, "PageSize": 100},
        )
        mock_registry.get_registry_record.assert_not_called()

    @patch("agentcore_app.check_timeout", side_effect=[True, False])
    @patch("agentcore_app.agent_registry_control_client")
    def test_registry_inventory_stops_during_pagination_when_timeout_approaches(
        self, mock_registry, mock_check_timeout
    ):
        mock_registry.get_paginator.return_value.paginate.return_value = [
            {
                "registries": [
                    {"registryId": "reg-1", "name": "registry-1", "status": "READY"}
                ]
            },
            {
                "registries": [
                    {"registryId": "reg-2", "name": "registry-2", "status": "READY"}
                ]
            },
        ]

        inventory = agentcore_app.get_agent_registry_inventory()

        assert inventory["timed_out"] is True
        assert inventory["timeout_stage"] == "listing registries"
        assert inventory["items"] == []
        mock_registry.get_registry.assert_not_called()
        assert mock_check_timeout.call_count == 2

    @patch("agentcore_app.check_timeout", side_effect=[True, True, False])
    @patch("agentcore_app.agent_registry_control_client")
    def test_registry_inventory_stops_before_detail_call_when_timeout_approaches(
        self, mock_registry, mock_check_timeout
    ):
        mock_registry.get_paginator.return_value.paginate.return_value = [
            {
                "registries": [
                    {"registryId": "reg-1", "name": "registry-1", "status": "READY"}
                ]
            }
        ]

        inventory = agentcore_app.get_agent_registry_inventory()

        assert inventory["timed_out"] is True
        assert inventory["timeout_stage"] == "retrieving registry details"
        assert inventory["items"] == []
        mock_registry.get_registry.assert_not_called()
        assert mock_check_timeout.call_count == 3

    @patch("agentcore_app.check_timeout", side_effect=[True, True, False])
    @patch("agentcore_app.agent_registry_control_client")
    def test_registry_record_inventory_stops_during_pagination(
        self, mock_registry, mock_check_timeout
    ):
        registry_inventory = {
            "items": [_registry_item()],
            "errors": [],
            "list_error": None,
            "unavailable": False,
        }
        paginator = mock_registry.get_paginator.return_value
        paginator.paginate.return_value = [
            {
                "registryRecords": [
                    {
                        "recordId": "record-1",
                        "name": "record-1",
                        "status": "APPROVED",
                        "createdBy": "123456789012",
                        "createdByAutoDetection": False,
                    }
                ]
            },
            {
                "registryRecords": [
                    {
                        "recordId": "record-2",
                        "name": "record-2",
                        "status": "DRAFT",
                        "createdBy": "111122223333",
                        "createdByAutoDetection": False,
                    }
                ]
            },
        ]

        inventory = agentcore_app.get_agent_registry_record_inventory(
            registry_inventory
        )

        assert inventory["timed_out"] is True
        assert inventory["timeout_stage"] == "listing registry records"
        assert inventory["records_seen"] == 1
        assert [item["summary"]["recordId"] for item in inventory["items"]] == [
            "record-1"
        ]
        assert mock_check_timeout.call_count == 3

    @patch.object(agentcore_app, "AGENT_REGISTRY_RECORD_INVENTORY_LIMIT", 1)
    @patch("agentcore_app.agent_registry_control_client")
    def test_registry_record_inventory_caps_and_marks_truncation(self, mock_registry):
        registry_inventory = {
            "items": [_registry_item()],
            "errors": [],
            "list_error": None,
            "unavailable": False,
        }
        page_iterator = MagicMock()
        page_iterator.__iter__.return_value = iter(
            [
                {
                    "registryRecords": [
                        {
                            "recordId": "record-1",
                            "name": "record-1",
                            "status": "APPROVED",
                            "createdBy": "123456789012",
                            "createdByAutoDetection": False,
                        }
                    ]
                }
            ]
        )
        page_iterator.resume_token = "remaining-records"
        paginator = mock_registry.get_paginator.return_value
        paginator.paginate.return_value = page_iterator

        inventory = agentcore_app.get_agent_registry_record_inventory(
            registry_inventory
        )

        assert inventory["truncated"] is True
        assert inventory["record_limit"] == 1
        assert inventory["records_seen"] == 1
        assert len(inventory["items"]) == 1
        paginator.paginate.assert_called_once_with(
            registryId="reg-1",
            PaginationConfig={"MaxItems": 1, "PageSize": 1},
        )

    @patch("agentcore_app.agent_registry_control_client")
    def test_registry_record_inventory_isolates_list_errors(self, mock_registry):
        registry_inventory = {
            "items": [_registry_item()],
            "errors": [],
            "list_error": None,
            "unavailable": False,
        }
        mock_registry.get_paginator.return_value.paginate.side_effect = (
            _make_client_error("AccessDeniedException", "Denied")
        )

        inventory = agentcore_app.get_agent_registry_record_inventory(
            registry_inventory
        )

        assert inventory["items"] == []
        assert len(inventory["list_errors"]) == 1

    def test_registry_timeout_propagates_as_incomplete_na(self):
        inventory = {
            "items": [],
            "errors": [],
            "list_error": None,
            "unavailable": False,
            "timed_out": True,
            "timeout_stage": "retrieving registry details",
        }

        finding = agentcore_app.check_agent_registry_approval_governance(inventory)[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "Lambda timeout was approaching" in finding["Finding_Details"]
        assert (
            "No AWS Agent Registry registries found" not in finding["Finding_Details"]
        )

    @pytest.mark.parametrize(
        "check_func",
        [
            agentcore_app.check_agent_registry_record_lifecycle,
            agentcore_app.check_agent_registry_record_provenance,
        ],
        ids=["lifecycle", "provenance"],
    )
    def test_registry_timeout_does_not_claim_records_are_absent(self, check_func):
        registry_inventory = {
            "items": [],
            "errors": [],
            "list_error": None,
            "unavailable": False,
            "timed_out": True,
            "timeout_stage": "listing registries",
        }
        record_inventory = _record_inventory(registry_inventory=registry_inventory)

        finding = check_func(record_inventory)[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "Lambda timeout was approaching" in finding["Finding_Details"]
        assert (
            "No AWS Agent Registry registries found" not in finding["Finding_Details"]
        )

    def test_registry_record_cap_preserves_results_and_emits_incomplete_na(self):
        inventory = _record_inventory(
            _record_item(status="APPROVED", record_id="record-1")
        )
        inventory.update(
            {
                "truncated": True,
                "record_limit": 1,
                "records_seen": 1,
                "timed_out": False,
            }
        )

        findings = agentcore_app.check_agent_registry_record_lifecycle(inventory)

        assert len(findings) == 2
        assert all(finding["Status"] == "N/A" for finding in findings)
        assert all(finding["Severity"] == "Informational" for finding in findings)
        incomplete = next(
            finding
            for finding in findings
            if "assessment limit" in finding["Finding_Details"]
        )
        assert "assessment limit of 1 records" in incomplete["Finding_Details"]

    def test_ac18_no_registries_returns_na(self):
        finding = agentcore_app.check_agent_registry_approval_governance(
            {"items": [], "errors": [], "list_error": None, "unavailable": False}
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert finding["Finding_Details"] == "No AWS Agent Registry registries found."

    @pytest.mark.parametrize(
        ("check", "uses_record_inventory"),
        [
            (agentcore_app.check_agent_registry_approval_governance, False),
            (agentcore_app.check_agent_registry_discovery_authorization, False),
            (agentcore_app.check_agent_registry_cmk_encryption, False),
            (agentcore_app.check_agent_registry_auto_detection, False),
            (agentcore_app.check_agent_registry_record_lifecycle, True),
            (agentcore_app.check_agent_registry_record_provenance, True),
        ],
    )
    def test_registry_checks_region_unavailable_return_na(
        self, check, uses_record_inventory
    ):
        registry_inventory = {
            "items": [],
            "errors": [],
            "list_error": _make_client_error("OptInRequired", "Region is not enabled"),
            "unavailable": True,
        }
        supplied_inventory = (
            _record_inventory(registry_inventory=registry_inventory)
            if uses_record_inventory
            else registry_inventory
        )

        finding = check(supplied_inventory)[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "not available" in finding["Finding_Details"]

    @pytest.mark.parametrize(
        ("error", "expected_resolution"),
        [
            (
                EndpointConnectionError(endpoint_url="https://agent-registry.invalid"),
                "Verify DNS resolution",
            ),
            (
                _make_client_error("ExpiredToken", "Token expired"),
                "Verify the assessment credentials",
            ),
            (
                _make_client_error("SignatureDoesNotMatch", "Bad signature"),
                "Verify the assessment credentials",
            ),
        ],
        ids=["endpoint", "expired-token", "bad-signature"],
    )
    @pytest.mark.parametrize(
        ("check", "uses_record_inventory"),
        [
            (agentcore_app.check_agent_registry_approval_governance, False),
            (agentcore_app.check_agent_registry_discovery_authorization, False),
            (agentcore_app.check_agent_registry_cmk_encryption, False),
            (agentcore_app.check_agent_registry_auto_detection, False),
            (agentcore_app.check_agent_registry_record_lifecycle, True),
            (agentcore_app.check_agent_registry_record_provenance, True),
        ],
    )
    def test_registry_transport_and_auth_failures_are_indeterminate(
        self,
        check,
        uses_record_inventory,
        error,
        expected_resolution,
    ):
        registry_inventory = {
            "items": [],
            "errors": [],
            "list_error": error,
            "unavailable": False,
        }
        supplied_inventory = (
            _record_inventory(registry_inventory=registry_inventory)
            if uses_record_inventory
            else registry_inventory
        )

        finding = check(supplied_inventory)[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "could not be assessed" in finding["Finding_Details"]
        assert "not available in this region" not in finding["Finding_Details"]
        assert expected_resolution in finding["Resolution"]

    @pytest.mark.parametrize(
        ("error", "expected_resolution", "expects_grant"),
        [
            (
                _make_client_error("AccessDeniedException", "Denied"),
                "Grant agent-registry:ListRegistries",
                True,
            ),
            (
                _make_client_error("ThrottlingException", "Slow down"),
                "throttling condition clears",
                False,
            ),
            (
                RuntimeError("unexpected list failure"),
                "Review the assessment logs",
                False,
            ),
        ],
        ids=["access-denied", "throttled", "unexpected-error"],
    )
    @pytest.mark.parametrize(
        "check",
        [
            agentcore_app.check_agent_registry_approval_governance,
            agentcore_app.check_agent_registry_discovery_authorization,
            agentcore_app.check_agent_registry_cmk_encryption,
            agentcore_app.check_agent_registry_auto_detection,
        ],
    )
    def test_registry_checks_list_errors_are_indeterminate(
        self, check, error, expected_resolution, expects_grant
    ):
        finding = check(
            {
                "items": [],
                "errors": [],
                "list_error": error,
                "unavailable": False,
            }
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "could not be assessed" in finding["Finding_Details"]
        assert expected_resolution in finding["Resolution"]
        assert ("Grant " in finding["Resolution"]) is expects_grant

    def test_record_checks_use_specific_list_registries_error_resolution(self):
        registry_inventory = {
            "items": [],
            "errors": [],
            "list_error": _make_client_error("ThrottlingException", "Slow down"),
            "initialization_error": None,
            "unavailable": False,
        }
        record_inventory = _record_inventory(registry_inventory=registry_inventory)

        finding = agentcore_app.check_agent_registry_record_lifecycle(record_inventory)[
            0
        ]

        assert finding["Status"] == "N/A"
        assert "throttling condition clears" in finding["Resolution"]
        assert "Grant " not in finding["Resolution"]

    def test_ac18_manual_approval_passes(self):
        finding = agentcore_app.check_agent_registry_approval_governance(
            {
                "items": [_registry_item()],
                "errors": [],
                "list_error": None,
                "unavailable": False,
            }
        )[0]

        assert finding["Check_ID"] == "AC-18"
        assert finding["Status"] == "Passed"
        assert "requires manual review" in finding["Finding_Details"]

    def test_ac18_absent_approval_configuration_returns_na(self):
        finding = agentcore_app.check_agent_registry_approval_governance(
            {
                "items": [_registry_item(approval_configuration=_OMITTED)],
                "errors": [],
                "list_error": None,
                "unavailable": False,
            }
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "optional approval configuration" in finding["Finding_Details"]
        assert "requires manual review" not in finding["Finding_Details"]

    @patch.dict(
        os.environ,
        {"REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL": "false"},
        clear=False,
    )
    def test_ac18_auto_approval_is_advisory_by_default(self):
        finding = agentcore_app.check_agent_registry_approval_governance(
            {
                "items": [
                    _registry_item(
                        approval_configuration={"autoApprovalRules": ["APPROVE_ALL"]}
                    )
                ],
                "errors": [],
                "list_error": None,
                "unavailable": False,
            }
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert finding["Resolution"] == (
            "No action required under the current baseline. Set "
            "REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL=true to require "
            "manual review for registry publication."
        )

    @patch.dict(
        os.environ,
        {"REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL": "true"},
        clear=False,
    )
    def test_ac18_auto_approval_fails_when_required(self):
        finding = agentcore_app.check_agent_registry_approval_governance(
            {
                "items": [
                    _registry_item(
                        approval_configuration={"autoApprovalRules": ["APPROVE_ALL"]}
                    )
                ],
                "errors": [],
                "list_error": None,
                "unavailable": False,
            }
        )[0]

        assert finding["Status"] == "Failed"
        assert finding["Severity"] == "Medium"
        assert finding["Resolution"] == (
            "Remove auto-approval rules so submitted records require manual review."
        )

    def test_ac18_detail_access_denied_does_not_hide_other_registries(self):
        inventory = {
            "items": [_registry_item(registry_id="reg-1")],
            "errors": [
                {
                    "summary": {"registryId": "reg-2", "name": "registry-2"},
                    "error": _make_client_error("AccessDeniedException", "Denied"),
                }
            ],
            "list_error": None,
            "unavailable": False,
        }

        findings = agentcore_app.check_agent_registry_approval_governance(inventory)

        assert {finding["Status"] for finding in findings} == {"Passed", "N/A"}
        assert all(finding["Check_ID"] == "AC-18" for finding in findings)

    def test_ac19_iam_authorization_requires_manual_review(self):
        finding = agentcore_app.check_agent_registry_discovery_authorization(
            {
                "items": [_registry_item()],
                "errors": [],
                "list_error": None,
                "unavailable": False,
            }
        )[0]

        assert finding["Check_ID"] == "AC-19"
        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "AWS IAM" in finding["Finding_Details"]
        assert "effective principals" in finding["Finding_Details"]
        assert "permissions boundaries" in finding["Resolution"]

    def test_ac19_no_registries_returns_na(self):
        finding = agentcore_app.check_agent_registry_discovery_authorization(
            {"items": [], "errors": [], "list_error": None, "unavailable": False}
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"

    def test_ac19_unconfigured_discovery_authorization_is_described_accurately(self):
        registry_item = _registry_item()
        registry_item["detail"].pop("discoveryConfiguration")

        finding = agentcore_app.check_agent_registry_discovery_authorization(
            {
                "items": [registry_item],
                "errors": [],
                "list_error": None,
                "unavailable": False,
            }
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert (
            "does not have discovery authorization configured"
            in finding["Finding_Details"]
        )
        assert "unrecognized" not in finding["Finding_Details"]
        assert finding["Resolution"] == (
            "No action required unless registry discovery is intended."
        )

    def test_ac19_constrained_custom_jwt_requires_manual_review(self):
        finding = agentcore_app.check_agent_registry_discovery_authorization(
            {
                "items": [
                    _registry_item(
                        discovery_configuration={
                            "authorizerType": "CUSTOM_JWT",
                            "authorizerConfiguration": {
                                "customJWTAuthorizer": {
                                    "discoveryUrl": "https://idp.example.com/.well-known/openid-configuration",
                                    "allowedAudience": ["registry-consumers"],
                                }
                            },
                        }
                    )
                ],
                "errors": [],
                "list_error": None,
                "unavailable": False,
            }
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "cannot determine" in finding["Finding_Details"]
        assert "approved registry consumer identities" in finding["Resolution"]

    def test_ac19_unconstrained_custom_jwt_fails(self):
        finding = agentcore_app.check_agent_registry_discovery_authorization(
            {
                "items": [
                    _registry_item(
                        discovery_configuration={
                            "authorizerType": "CUSTOM_JWT",
                            "authorizerConfiguration": {
                                "customJWTAuthorizer": {
                                    "discoveryUrl": "https://idp.example.com/.well-known/openid-configuration"
                                }
                            },
                        }
                    )
                ],
                "errors": [],
                "list_error": None,
                "unavailable": False,
            }
        )[0]

        assert finding["Status"] == "Failed"
        assert finding["Severity"] == "High"

    def test_ac19_unknown_authorizer_is_na(self):
        finding = agentcore_app.check_agent_registry_discovery_authorization(
            {
                "items": [
                    _registry_item(
                        discovery_configuration={"authorizerType": "FUTURE_AUTH"}
                    )
                ],
                "errors": [],
                "list_error": None,
                "unavailable": False,
            }
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"

    def test_ac20_customer_managed_key_passes(self):
        finding = agentcore_app.check_agent_registry_cmk_encryption(
            {
                "items": [
                    _registry_item(
                        encryption_configuration={
                            "kmsKeyArn": (
                                "arn:aws:kms:us-east-1:123456789012:"
                                "key/11111111-2222-3333-4444-555555555555"
                            )
                        }
                    )
                ],
                "errors": [],
                "list_error": None,
                "unavailable": False,
            }
        )[0]

        assert finding["Check_ID"] == "AC-20"
        assert finding["Status"] == "Passed"
        assert finding["Severity"] == "Medium"

    @patch.dict(os.environ, {"REQUIRE_AGENT_REGISTRY_CMK": "false"}, clear=False)
    def test_ac20_aws_owned_key_is_advisory_by_default(self):
        finding = agentcore_app.check_agent_registry_cmk_encryption(
            {
                "items": [_registry_item()],
                "errors": [],
                "list_error": None,
                "unavailable": False,
            }
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "AWS owned key" in finding["Finding_Details"]

    @patch.dict(os.environ, {"REQUIRE_AGENT_REGISTRY_CMK": "true"}, clear=False)
    def test_ac20_aws_owned_key_fails_when_required(self):
        finding = agentcore_app.check_agent_registry_cmk_encryption(
            {
                "items": [_registry_item()],
                "errors": [],
                "list_error": None,
                "unavailable": False,
            }
        )[0]

        assert finding["Status"] == "Failed"
        assert finding["Severity"] == "Medium"
        assert "replacement registry" in finding["Resolution"]

    def test_ac21_active_organization_auto_detection_passes(self):
        finding = agentcore_app.check_agent_registry_auto_detection(
            {
                "items": [
                    _registry_item(
                        auto_detection={
                            "configuration": {
                                "enabled": True,
                                "scope": "ORGANIZATION",
                            },
                            "status": "ACTIVE",
                        }
                    )
                ],
                "errors": [],
                "list_error": None,
                "unavailable": False,
            }
        )[0]

        assert finding["Check_ID"] == "AC-21"
        assert finding["Status"] == "Passed"
        assert finding["Severity"] == "Medium"

    @pytest.mark.parametrize(
        ("auto_detection", "expected_text"),
        [
            (None, "does not have organization auto-detection configured"),
            (
                {
                    "configuration": {"enabled": False, "scope": "ORGANIZATION"},
                    "status": "INACTIVE",
                },
                "disabled",
            ),
            (
                {
                    "configuration": {"enabled": True, "scope": "ORGANIZATION"},
                    "status": "INACTIVE",
                },
                "preconditions",
            ),
        ],
        ids=["not-configured", "disabled", "inactive"],
    )
    def test_ac21_non_active_states_are_advisory(self, auto_detection, expected_text):
        finding = agentcore_app.check_agent_registry_auto_detection(
            {
                "items": [_registry_item(auto_detection=auto_detection)],
                "errors": [],
                "list_error": None,
                "unavailable": False,
            }
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert expected_text in finding["Finding_Details"]

    @pytest.mark.parametrize(
        "status",
        ["DRAFT", "PENDING_APPROVAL", "APPROVED", "REJECTED", "DEPRECATED"],
    )
    def test_ac22_governed_lifecycle_states_are_advisory(self, status):
        finding = agentcore_app.check_agent_registry_record_lifecycle(
            _record_inventory(_record_item(status=status))
        )[0]

        assert finding["Check_ID"] == "AC-22"
        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert status in finding["Finding_Details"]

    @pytest.mark.parametrize(
        "status",
        ["CREATING", "UPDATING", "CREATE_FAILED", "UPDATE_FAILED", "FUTURE_STATE"],
    )
    def test_ac22_transitional_failed_and_unknown_states_are_indeterminate(
        self, status
    ):
        finding = agentcore_app.check_agent_registry_record_lifecycle(
            _record_inventory(_record_item(status=status))
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"

    def test_ac22_no_records_returns_na(self):
        finding = agentcore_app.check_agent_registry_record_lifecycle(
            _record_inventory()
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Finding_Details"] == "No AWS Agent Registry records found."

    def test_ac22_record_list_access_denied_is_indeterminate(self):
        inventory = _record_inventory()
        inventory["list_errors"] = [
            {
                "registry": _registry_item(),
                "error": _make_client_error("AccessDeniedException", "Denied"),
            }
        ]

        finding = agentcore_app.check_agent_registry_record_lifecycle(inventory)[0]

        assert finding["Status"] == "N/A"
        assert (
            "ListRegistryRecords returned AccessDeniedException"
            in finding["Finding_Details"]
        )
        assert finding["Resolution"] == (
            "Grant agent-registry:ListRegistryRecords and retry the assessment."
        )

    def test_ac22_incomplete_record_summary_does_not_hide_other_records(self):
        inventory = _record_inventory(_record_item(record_id="record-1"))
        inventory["errors"] = [
            {
                "registry": _registry_item(),
                "summary": {
                    "recordId": "record-2",
                    "name": "record-2",
                    "status": "APPROVED",
                },
                "error": ValueError(
                    "Registry record summary did not include an identifier"
                ),
            }
        ]

        findings = agentcore_app.check_agent_registry_record_lifecycle(inventory)

        assert len(findings) == 2
        assert all(finding["Status"] == "N/A" for finding in findings)
        incomplete = next(
            finding
            for finding in findings
            if "incomplete metadata" in finding["Finding_Details"]
        )
        assert "incomplete metadata" in incomplete["Finding_Details"]
        assert "Grant " not in incomplete["Resolution"]

    def test_registry_throttling_resolution_does_not_recommend_iam_change(self):
        inventory = {
            "items": [],
            "errors": [
                {
                    "summary": {"registryId": "reg-1", "name": "registry-1"},
                    "error": _make_client_error("ThrottlingException", "Slow down"),
                }
            ],
            "list_error": None,
            "unavailable": False,
        }

        finding = agentcore_app.check_agent_registry_approval_governance(inventory)[0]

        assert finding["Status"] == "N/A"
        assert "throttling condition clears" in finding["Resolution"]
        assert "Grant " not in finding["Resolution"]

    @patch("agentcore_app.get_agent_registry_inventory")
    def test_ac22_supplied_record_inventory_does_not_refetch_registries(
        self, mock_get_registry_inventory
    ):
        finding = agentcore_app.check_agent_registry_record_lifecycle(
            _record_inventory(_record_item())
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        mock_get_registry_inventory.assert_not_called()

    @patch("agentcore_app.get_agent_registry_inventory")
    def test_ac23_supplied_record_inventory_does_not_refetch_registries(
        self, mock_get_registry_inventory
    ):
        finding = agentcore_app.check_agent_registry_record_provenance(
            _record_inventory(_record_item())
        )[0]

        assert finding["Status"] == "Passed"
        mock_get_registry_inventory.assert_not_called()

    def test_ac23_auto_detected_record_with_provenance_passes(self):
        finding = agentcore_app.check_agent_registry_record_provenance(
            _record_inventory(
                _record_item(
                    created_by="111122223333",
                    created_by_auto_detection=True,
                    provenance=[
                        {
                            "relation": "DETECTED_FROM",
                            "sourceId": (
                                "arn:aws:bedrock-agentcore:us-east-1:"
                                "111122223333:runtime/runtime-1"
                            ),
                            "sourceType": "AWS::BedrockAgentCore::Runtime",
                        }
                    ],
                )
            )
        )[0]

        assert finding["Check_ID"] == "AC-23"
        assert finding["Status"] == "Passed"
        assert finding["Severity"] == "Medium"

    def test_ac23_auto_detected_gateway_provenance_passes(self):
        finding = agentcore_app.check_agent_registry_record_provenance(
            _record_inventory(
                _record_item(
                    created_by="111122223333",
                    created_by_auto_detection=True,
                    provenance=[
                        {
                            "relation": "DETECTED_FROM",
                            "sourceId": (
                                "arn:aws-us-gov:bedrock-agentcore:us-gov-west-1:"
                                "111122223333:gateway/gateway-1"
                            ),
                            "sourceType": "AWS::BedrockAgentCore::Gateway",
                        }
                    ],
                )
            )
        )[0]

        assert finding["Status"] == "Passed"

    def test_ac23_auto_detected_record_without_optional_source_type_returns_na(self):
        finding = agentcore_app.check_agent_registry_record_provenance(
            _record_inventory(
                _record_item(
                    created_by_auto_detection=True,
                    provenance=[
                        {
                            "relation": "DETECTED_FROM",
                            "sourceId": (
                                "arn:aws:bedrock-agentcore:us-east-1:"
                                "111122223333:runtime/runtime-1"
                            ),
                        }
                    ],
                )
            )
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "optional provenance source type" in finding["Finding_Details"]

    @pytest.mark.parametrize(
        "provenance",
        [None, []],
        ids=["missing", "empty"],
    )
    def test_ac23_auto_detected_record_without_provenance_returns_na(self, provenance):
        finding = agentcore_app.check_agent_registry_record_provenance(
            _record_inventory(
                _record_item(
                    created_by_auto_detection=True,
                    provenance=provenance,
                )
            )
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "optional provenance metadata" in finding["Finding_Details"]
        assert "Refresh or recreate" not in finding["Resolution"]

    def test_ac23_invalid_entry_outranks_missing_source_type(self):
        finding = agentcore_app.check_agent_registry_record_provenance(
            _record_inventory(
                _record_item(
                    created_by_auto_detection=True,
                    provenance=[
                        {
                            "relation": "DETECTED_FROM",
                            "sourceId": (
                                "arn:aws:bedrock-agentcore:us-east-1:"
                                "111122223333:gateway/gateway-1"
                            ),
                            "sourceType": "AWS::BedrockAgentCore::Runtime",
                        },
                        {
                            "relation": "DETECTED_FROM",
                            "sourceId": "not-an-arn",
                        },
                    ],
                )
            )
        )[0]

        assert finding["Status"] == "Failed"
        assert finding["Severity"] == "Medium"
        assert (
            "does not include valid DETECTED_FROM provenance"
            in (finding["Finding_Details"])
        )

    @pytest.mark.parametrize(
        "provenance",
        [
            [
                {
                    "relation": "COPIED_FROM",
                    "sourceId": (
                        "arn:aws:bedrock-agentcore:us-east-1:"
                        "111122223333:runtime/runtime-1"
                    ),
                    "sourceType": "AWS::BedrockAgentCore::Runtime",
                }
            ],
            [
                {
                    "relation": "DETECTED_FROM",
                    "sourceId": "not-an-arn",
                    "sourceType": "AWS::BedrockAgentCore::Runtime",
                }
            ],
            [
                {
                    "relation": "DETECTED_FROM",
                    "sourceId": (
                        "arn:aws:lambda:us-east-1:111122223333:function:source-function"
                    ),
                    "sourceType": "AWS::BedrockAgentCore::Runtime",
                }
            ],
            [
                {
                    "relation": "DETECTED_FROM",
                    "sourceId": (
                        "arn:aws:bedrock-agentcore:us-east-1:"
                        "111122223333:gateway/gateway-1"
                    ),
                    "sourceType": "AWS::BedrockAgentCore::Runtime",
                }
            ],
            [
                {
                    "relation": "DETECTED_FROM",
                    "sourceId": (
                        "arn:aws:bedrock-agentcore:us-east-1:"
                        "111122223333:runtime/runtime-1"
                    ),
                    "sourceType": "AWS::BedrockAgentCore::Gateway",
                }
            ],
        ],
        ids=[
            "wrong-relation",
            "invalid-source",
            "wrong-service",
            "gateway-arn-as-runtime",
            "runtime-arn-as-gateway",
        ],
    )
    def test_ac23_auto_detected_record_without_valid_provenance_fails(self, provenance):
        finding = agentcore_app.check_agent_registry_record_provenance(
            _record_inventory(
                _record_item(
                    created_by_auto_detection=True,
                    provenance=provenance,
                )
            )
        )[0]

        assert finding["Status"] == "Failed"
        assert finding["Severity"] == "Medium"

    def test_ac23_manual_record_with_creator_account_passes(self):
        finding = agentcore_app.check_agent_registry_record_provenance(
            _record_inventory(
                _record_item(
                    created_by="444455556666",
                    created_by_auto_detection=False,
                )
            )
        )[0]

        assert finding["Status"] == "Passed"
        assert "444455556666" in finding["Finding_Details"]

    def test_ac23_missing_origin_mode_metadata_returns_na(self):
        finding = agentcore_app.check_agent_registry_record_provenance(
            _record_inventory(
                _record_item(
                    created_by=None,
                    created_by_auto_detection=None,
                )
            )
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"

    def test_ac23_manual_record_without_optional_creator_account_returns_na(self):
        finding = agentcore_app.check_agent_registry_record_provenance(
            _record_inventory(
                _record_item(
                    created_by=None,
                    created_by_auto_detection=False,
                )
            )
        )[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "optional creator account attribution" in finding["Finding_Details"]

    @pytest.mark.parametrize("created_by", ["invalid"])
    def test_ac23_manual_record_without_creator_account_fails(self, created_by):
        finding = agentcore_app.check_agent_registry_record_provenance(
            _record_inventory(
                _record_item(
                    created_by=created_by,
                    created_by_auto_detection=False,
                )
            )
        )[0]

        assert finding["Status"] == "Failed"
        assert finding["Severity"] == "Medium"
        assert "manually created" in finding["Finding_Details"].lower()
        assert "valid 12-digit creator account ID" in finding["Finding_Details"]


# ===================================================================
# lambda_handler: multi-region gating and availability probe
# ===================================================================
def _agentcore_event(region="us-east-1", region_index=0):
    return {
        "Region": region,
        "RegionIndex": region_index,
        "Execution": {"Name": "test-execution-1"},
        "StateMachine": {"Name": "test-sm"},
    }


def _valid_slr_role():
    """A valid service-linked-role get_role response so AC-09 passes cleanly."""
    return {
        "Role": {
            "RoleName": "AWSServiceRoleForBedrockAgentCoreNetwork",
            "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "agentcore.bedrock.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ]
            },
        }
    }


class TestAgentCoreHandlerMultiRegion:
    """lambda_handler primary-region gating (AC-02/AC-03/AC-09) + availability probe (AC-00)."""

    def _run_handler(
        self,
        agentcore_side_effect,
        event,
        registry_inventory=None,
        registry_record_inventory=None,
        registry_inventory_side_effect=None,
    ):
        """Run the handler with a per-service boto3.client dispatch. The
        bedrock-agentcore-control probe (list_agent_runtimes) uses
        agentcore_side_effect to simulate availability; iam is given a valid SLR
        response. Returns (response, findings) where findings is the flat list
        passed to generate_csv_report."""
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        iam_mock = MagicMock()
        iam_mock.get_role.return_value = _valid_slr_role()
        iam_mock.exceptions.NoSuchEntityException = type(
            "NoSuchEntityException", (Exception,), {}
        )

        sts_mock = MagicMock()
        sts_mock.get_caller_identity.return_value = {"Account": "123456789012"}

        agentcore_mock = MagicMock()
        agentcore_mock.list_agent_runtimes.side_effect = agentcore_side_effect

        def client_dispatch(service, *args, **kwargs):
            if service == "iam":
                return iam_mock
            if service == "sts":
                return sts_mock
            if service == "bedrock-agentcore-control":
                return agentcore_mock
            return MagicMock()

        effective_registry_inventory = registry_inventory or {
            "items": [],
            "errors": [],
            "list_error": None,
            "unavailable": False,
        }
        effective_record_inventory = registry_record_inventory or _record_inventory(
            registry_inventory=effective_registry_inventory
        )
        registry_inventory_patch = {
            "return_value": effective_registry_inventory,
        }
        if registry_inventory_side_effect is not None:
            registry_inventory_patch = {
                "side_effect": registry_inventory_side_effect,
            }

        with (
            patch("agentcore_app.boto3.client", side_effect=client_dispatch),
            patch.object(
                agentcore_app,
                "get_permissions_cache",
                return_value={"role_permissions": {}, "user_permissions": {}},
            ),
            patch.object(
                agentcore_app,
                "get_agent_registry_inventory",
                **registry_inventory_patch,
            ),
            patch.object(
                agentcore_app,
                "get_agent_registry_record_inventory",
                return_value=effective_record_inventory,
            ),
            patch.object(agentcore_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(agentcore_app, "write_to_s3", return_value="s3://b/r.csv"),
        ):
            resp = agentcore_app.lambda_handler(event, None)

        return resp, captured.get("findings", [])

    @patch("agentcore_app.check_timeout", return_value=False)
    def test_registry_inventory_is_not_fetched_after_timeout_guard(
        self, mock_check_timeout
    ):
        resp, _ = self._run_handler(
            EndpointConnectionError(endpoint_url="https://agentcore.invalid"),
            _agentcore_event(region="us-east-1", region_index=1),
            registry_inventory_side_effect=AssertionError(
                "Registry inventory should not be fetched after timeout"
            ),
        )

        assert resp["statusCode"] == 200
        mock_check_timeout.assert_called()

    @patch(
        "agentcore_app.check_timeout",
        side_effect=[True, True, False, False],
    )
    def test_registry_timeout_backfills_skipped_checks(self, mock_check_timeout):
        resp, findings = self._run_handler(
            EndpointConnectionError(endpoint_url="https://agentcore.invalid"),
            _agentcore_event(region="us-east-1", region_index=1),
        )

        assert resp["statusCode"] == 200
        status_by_id = {finding["Check_ID"]: finding["Status"] for finding in findings}
        assert status_by_id["AC-18"] == "N/A"
        assert status_by_id["AC-19"] == "N/A"
        assert status_by_id["AC-23"] == "N/A"
        assert status_by_id["AC-01"] == "N/A"
        assert status_by_id["AC-17"] == "N/A"
        assert status_by_id["AG-15"] == "N/A"
        assert status_by_id["AG-38"] == "N/A"
        assert mock_check_timeout.call_count == 4

    def test_registry_inventory_timeout_writes_backfilled_partial_report(self):
        timed_out_inventory = {
            "items": [],
            "errors": [],
            "list_error": None,
            "unavailable": False,
            "timed_out": True,
            "timeout_stage": "listing registries",
        }

        resp, findings = self._run_handler(
            AssertionError("AgentCore availability probe should not run"),
            _agentcore_event(region="us-east-1", region_index=1),
            registry_inventory=timed_out_inventory,
        )

        assert resp["statusCode"] == 200
        status_by_id = {finding["Check_ID"]: finding["Status"] for finding in findings}
        assert status_by_id["AC-18"] == "N/A"
        assert status_by_id["AC-23"] == "N/A"
        assert status_by_id["AC-01"] == "N/A"
        assert status_by_id["AC-17"] == "N/A"
        assert status_by_id["AG-15"] == "N/A"
        assert status_by_id["AG-38"] == "N/A"
        assert all(
            finding["Severity"] == "Informational"
            for finding in findings
            if finding["Check_ID"] in {"AC-01", "AC-17", "AG-15", "AG-38"}
        )

    def test_primary_region_emits_global_iam_checks_tagged_global(self):
        # On the primary region, AC-02, AC-03 and AC-09 (all IAM-global) must be
        # emitted and tagged "Global", even when AgentCore is unavailable.
        resp, findings = self._run_handler(
            EndpointConnectionError(endpoint_url="https://agentcore.invalid"),
            _agentcore_event(region="ap-south-2", region_index=0),
        )
        assert resp["statusCode"] == 200

        check_ids = {f["Check_ID"] for f in findings}
        assert "AC-02" in check_ids
        assert "AC-03" in check_ids
        assert "AC-09" in check_ids
        for f in findings:
            if f["Check_ID"] in ("AC-02", "AC-03", "AC-09"):
                assert f["Region"] == "Global"
        # The availability finding is tagged with the scanned region.
        ac00 = [f for f in findings if f["Check_ID"] == "AC-00"]
        assert ac00 and ac00[0]["Region"] == "ap-south-2"

    def test_non_primary_region_skips_global_iam_checks(self):
        # On a non-primary region the IAM-global checks must NOT run.
        resp, findings = self._run_handler(
            EndpointConnectionError(endpoint_url="https://agentcore.invalid"),
            _agentcore_event(region="eu-west-1", region_index=3),
        )
        assert resp["statusCode"] == 200

        check_ids = {f["Check_ID"] for f in findings}
        assert "AC-02" not in check_ids
        assert "AC-03" not in check_ids
        assert "AC-09" not in check_ids
        expected_agentic_ids = {f"AG-{i:02d}" for i in range(15, 28)} | {
            "AG-28",
            "AG-29",
            "AG-31",
            "AG-32",
            "AG-33",
            "AG-34",
            "AG-35",
            "AG-36",
            "AG-37",
            "AG-38",
        }
        assert (
            check_ids
            == {
                "AC-00",
                "AC-18",
                "AC-19",
                "AC-20",
                "AC-21",
                "AC-22",
                "AC-23",
            }
            | expected_agentic_ids
        )

    def test_registry_checks_run_when_agentcore_runtime_is_unavailable(self):
        registry_item = _registry_item(
            encryption_configuration={
                "kmsKeyArn": (
                    "arn:aws:kms:us-east-1:123456789012:"
                    "key/11111111-2222-3333-4444-555555555555"
                )
            },
            auto_detection={
                "configuration": {"enabled": True, "scope": "ORGANIZATION"},
                "status": "ACTIVE",
            },
        )
        registry_inventory = {
            "items": [registry_item],
            "errors": [],
            "list_error": None,
            "unavailable": False,
        }
        registry_record_inventory = _record_inventory(
            _record_item(registry_item=registry_item),
            registry_inventory=registry_inventory,
        )

        resp, findings = self._run_handler(
            EndpointConnectionError(endpoint_url="https://agentcore.invalid"),
            _agentcore_event(region="us-east-1", region_index=1),
            registry_inventory=registry_inventory,
            registry_record_inventory=registry_record_inventory,
        )

        assert resp["statusCode"] == 200
        status_by_id = {
            finding["Check_ID"]: finding["Status"]
            for finding in findings
            if finding["Check_ID"]
            in {
                "AC-18",
                "AC-19",
                "AC-20",
                "AC-21",
                "AC-22",
                "AC-23",
                "AG-33",
                "AG-34",
                "AG-35",
                "AG-36",
                "AG-37",
                "AG-38",
            }
        }
        assert status_by_id == {
            "AC-18": "Passed",
            "AC-19": "N/A",
            "AC-20": "Passed",
            "AC-21": "Passed",
            "AC-22": "N/A",
            "AC-23": "Passed",
            "AG-33": "Passed",
            "AG-34": "N/A",
            "AG-35": "Passed",
            "AG-36": "Passed",
            "AG-37": "N/A",
            "AG-38": "Passed",
        }

    def test_optin_region_error_treated_as_unavailable(self):
        # A region-not-enabled ClientError code makes agentcore_client None, so
        # the handler emits the AC-00 availability finding and exits early.
        resp, findings = self._run_handler(
            _make_client_error("OptInRequired"),
            _agentcore_event(region="me-south-1", region_index=1),
        )
        assert resp["statusCode"] == 200
        ac00 = [f for f in findings if f["Check_ID"] == "AC-00"]
        assert ac00 and ac00[0]["Status"] == "N/A"

    @pytest.mark.parametrize(
        "error_code",
        sorted(agentcore_app.AUTHENTICATION_ERROR_CODES),
    )
    def test_runtime_auth_probe_errors_emit_incomplete_na_and_preserve_registry(
        self, error_code
    ):
        registry_item = _registry_item(
            encryption_configuration={
                "kmsKeyArn": (
                    "arn:aws:kms:us-east-1:123456789012:"
                    "key/11111111-2222-3333-4444-555555555555"
                )
            },
            auto_detection={
                "configuration": {"enabled": True, "scope": "ORGANIZATION"},
                "status": "ACTIVE",
            },
        )
        registry_inventory = {
            "items": [registry_item],
            "errors": [],
            "list_error": None,
            "unavailable": False,
        }
        registry_record_inventory = _record_inventory(
            _record_item(registry_item=registry_item),
            registry_inventory=registry_inventory,
        )

        resp, findings = self._run_handler(
            _make_client_error(error_code, "Rejected assessment credentials"),
            _agentcore_event(region="us-east-1", region_index=1),
            registry_inventory=registry_inventory,
            registry_record_inventory=registry_record_inventory,
        )

        assert resp["statusCode"] == 200
        assert not [finding for finding in findings if finding["Status"] == "Failed"]

        status_by_id = {finding["Check_ID"]: finding["Status"] for finding in findings}
        assert status_by_id["AC-18"] == "Passed"
        assert status_by_id["AC-20"] == "Passed"
        assert status_by_id["AC-21"] == "Passed"
        assert status_by_id["AC-23"] == "Passed"
        assert status_by_id["AG-33"] == "Passed"
        assert status_by_id["AG-38"] == "Passed"

        mapped_runtime_ids = {
            agentcore_app.AGENTIC_AGENTCORE_CHECK_MAPPINGS[check_id]["check_id"]
            for check_id in agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS
            if check_id in agentcore_app.AGENTIC_AGENTCORE_CHECK_MAPPINGS
        }
        incomplete_ids = {
            "AC-00",
            *agentcore_app.AGENTCORE_RUNTIME_CHECK_IDS,
            *agentcore_app.NATIVE_AGENTIC_AGENTCORE_CHECK_NAMES,
            *mapped_runtime_ids,
        }
        incomplete_findings = [
            finding for finding in findings if finding["Check_ID"] in incomplete_ids
        ]
        assert {
            finding["Check_ID"] for finding in incomplete_findings
        } == incomplete_ids
        assert all(finding["Status"] == "N/A" for finding in incomplete_findings)
        assert all(
            finding["Severity"] == "Informational" for finding in incomplete_findings
        )
        assert all(
            "not available in this region" not in finding["Finding_Details"]
            for finding in incomplete_findings
        )
        assert all(
            "Verify the assessment credentials" in finding["Resolution"]
            for finding in incomplete_findings
        )

    def test_access_denied_probe_proceeds_with_checks(self):
        # AccessDenied is NOT a region-unavailable code: the service is reachable,
        # so the handler proceeds and runs regional checks (no AC-00 emitted).
        resp, findings = self._run_handler(
            _make_client_error("AccessDeniedException"),
            _agentcore_event(region="us-east-1", region_index=0),
        )
        assert resp["statusCode"] == 200
        check_ids = {f["Check_ID"] for f in findings}
        assert "AC-00" not in check_ids
        # Regional checks ran (e.g. AC-01 VPC, AC-04 observability present).
        assert len(check_ids) > 3

    def test_unexpected_probe_error_proceeds_with_checks(self):
        # An unexpected, non-ClientError probe failure (e.g. a boto3/botocore SDK
        # param/operation mismatch surfacing as ParamValidationError) says nothing
        # about regional availability. The handler must NOT treat it as
        # unavailable (which would emit a false AC-00 N/A and skip every check);
        # it should proceed and run the regional checks.
        try:
            from botocore.exceptions import ParamValidationError

            probe_error = ParamValidationError(
                report="maxResults is not a valid parameter"
            )
        except Exception:
            probe_error = TypeError("unexpected SDK signature")

        resp, findings = self._run_handler(
            probe_error,
            _agentcore_event(region="us-east-1", region_index=0),
        )
        assert resp["statusCode"] == 200
        check_ids = {f["Check_ID"] for f in findings}
        # No false "not available" finding, and the regional checks executed.
        assert "AC-00" not in check_ids
        assert len(check_ids) > 3
