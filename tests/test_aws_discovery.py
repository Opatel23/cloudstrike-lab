import unittest
from pathlib import Path

from cloudstrike.discovery.aws import AwsLabDiscovery
from cloudstrike.graph import AttackGraph
from cloudstrike.planning import build_dry_run
from cloudstrike.safety import LabManifest, SafetyViolation


FIXTURE = Path(__file__).parent / "fixtures" / "terraform-output.json"
TAGS = [{"Key": "Project", "Value": "cloudstrike-lab"}, {"Key": "LabID", "Value": "cloudstrike-lab-iam-passrole"}]


class Sts:
    def __init__(self, account="123456789012"):
        self.account = account
    def get_caller_identity(self):
        return {"Account": self.account}


class Secrets:
    def describe_secret(self, SecretId):
        return {"ARN": SecretId, "Tags": TAGS}


class Iam:
    def get_role(self, RoleName):
        return {"Role": {"RoleName": RoleName, "Tags": TAGS}}
    def list_role_policies(self, RoleName):
        return {"PolicyNames": ["app"] if "app" in RoleName else ["secret"]}
    def get_role_policy(self, RoleName, PolicyName):
        if PolicyName == "app":
            return {"PolicyDocument": {"Statement": [
                {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::123456789012:role/cloudstrike-lab-lambda-privileged-test"},
                {"Effect": "Allow", "Action": "lambda:CreateFunction", "Resource": "arn:aws:lambda:us-east-1:123456789012:function:cloudstrike-lab-*"}
            ]}}
        return {"PolicyDocument": {"Statement": {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:cloudstrike-lab/demo-database-test"}}}


def clients(service, region, account="123456789012"):
    return {"sts": Sts(account), "iam": Iam(), "secretsmanager": Secrets()}[service]


class AwsDiscoveryTests(unittest.TestCase):
    def test_discovers_live_policy_chain_and_dry_run_executes_nothing(self):
        manifest = LabManifest.from_terraform_output(FIXTURE)
        inventory = AwsLabDiscovery(manifest, clients).discover()
        path = AttackGraph(inventory).paths_to_critical("principal:compromised-app")[0]
        self.assertEqual(path.length, 4)
        plan = build_dry_run(inventory, manifest)
        self.assertTrue(plan["path_found"])
        self.assertEqual(plan["executed_actions"], 0)
        self.assertNotIn("iam:PassRole", [action["api_action"] for action in plan["planned_actions"]])

    def test_wrong_account_is_rejected_before_resource_discovery(self):
        manifest = LabManifest.from_terraform_output(FIXTURE)
        def wrong_clients(service, region):
            return clients(service, region, "999999999999")
        with self.assertRaisesRegex(SafetyViolation, "does not match"):
            AwsLabDiscovery(manifest, wrong_clients).discover()

