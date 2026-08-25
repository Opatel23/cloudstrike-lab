from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cloudstrike.model import Edge, EdgeType, Inventory, Node
from cloudstrike.safety import LabManifest, require_lab_tags


def _role_name(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


def _items(value: str | list[str] | None) -> set[str]:
    if value is None:
        return set()
    return {value} if isinstance(value, str) else set(value)


def _allows(document: dict[str, Any], action: str, resource: str) -> bool:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        actions = _items(statement.get("Action"))
        resources = _items(statement.get("Resource"))
        action_allowed = action in actions or "*" in actions or action.split(":")[0] + ":*" in actions
        resource_allowed = resource in resources or "*" in resources
        if action_allowed and resource_allowed:
            return True
    return False


class AwsLabDiscovery:
    """Scenario-specific, read-only AWS discovery with fail-closed identity and tag checks."""

    def __init__(self, manifest: LabManifest, client_factory: Callable[[str, str], Any]):
        self.manifest = manifest
        self.client_factory = client_factory

    def discover(self) -> Inventory:
        sts = self.client_factory("sts", self.manifest.region)
        self.manifest.assert_caller(sts.get_caller_identity()["Account"])
        iam = self.client_factory("iam", self.manifest.region)
        secrets = self.client_factory("secretsmanager", self.manifest.region)

        app_name = _role_name(self.manifest.app_role_arn)
        privileged_name = _role_name(self.manifest.privileged_role_arn)
        app_role = iam.get_role(RoleName=app_name)["Role"]
        privileged_role = iam.get_role(RoleName=privileged_name)["Role"]
        require_lab_tags(app_role.get("Tags", []), self.manifest.lab_id)
        require_lab_tags(privileged_role.get("Tags", []), self.manifest.lab_id)
        require_lab_tags(secrets.describe_secret(SecretId=self.manifest.secret_arn).get("Tags", []), self.manifest.lab_id)

        app_policies = self._inline_policies(iam, app_name)
        privileged_policies = self._inline_policies(iam, privileged_name)
        can_pass = any(_allows(policy, "iam:PassRole", self.manifest.privileged_role_arn) for policy in app_policies)
        function_pattern = f"arn:aws:lambda:{self.manifest.region}:{self.manifest.account_id}:function:cloudstrike-lab-*"
        can_create = any(_allows(policy, "lambda:CreateFunction", function_pattern) for policy in app_policies)
        can_read = any(_allows(policy, "secretsmanager:GetSecretValue", self.manifest.secret_arn) for policy in privileged_policies)

        nodes = [
            Node("principal:compromised-app", "principal", "Compromised public application", "untrusted"),
            Node("role:app", "iam_role", app_name, "low", tags={"arn": self.manifest.app_role_arn}),
            Node("capability:pass-lambda-admin", "capability", "PassRole grant", "dangerous"),
            Node("role:lambda-admin", "iam_role", privileged_name, "privileged", tags={"arn": self.manifest.privileged_role_arn}),
            Node("lambda:attacker-workload", "potential_workload", "Controlled lab function", "low"),
            Node("secret:crown-jewel", "secret", "Demo database secret", "critical", True, {"arn": self.manifest.secret_arn}),
        ]
        edges = [
            Edge("principal:compromised-app", "role:app", EdgeType.CAN_ASSUME, "Approved lab starting premise", ("sts:AssumeRole",)),
        ]
        if can_pass:
            edges.append(Edge("role:app", "capability:pass-lambda-admin", EdgeType.CAN_PASS_ROLE, "Live inline IAM policy permits the exact privileged role", ("iam:PassRole",), "role:app", {"role": "role:lambda-admin"}))
        if can_create:
            edges.append(Edge("capability:pass-lambda-admin", "lambda:attacker-workload", EdgeType.CAN_CREATE_FUNCTION, "Live inline IAM policy permits only CloudStrike lab function names", ("lambda:CreateFunction",), "role:app", {"role": "role:lambda-admin"}))
        if can_read:
            edges.append(Edge("lambda:attacker-workload", "secret:crown-jewel", EdgeType.CAN_READ, "Privileged role live policy permits the exact demo secret", ("secretsmanager:GetSecretValue",), "lambda:attacker-workload"))
        return Inventory(nodes, edges, self.manifest.lab_id)

    @staticmethod
    def _inline_policies(iam: Any, role_name: str) -> list[dict[str, Any]]:
        names = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
        return [iam.get_role_policy(RoleName=role_name, PolicyName=name)["PolicyDocument"] for name in names]


def boto3_client_factory(service: str, region: str) -> Any:
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("Install the AWS extra first: python -m pip install -e '.[aws]'") from exc
    return boto3.client(service, region_name=region)

