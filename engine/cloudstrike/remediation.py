from __future__ import annotations

from dataclasses import dataclass

from cloudstrike.model import AttackPath, Edge, EdgeType


@dataclass(frozen=True)
class Remediation:
    finding: str
    root_cause_edge: Edge
    remove_actions: tuple[str, ...]
    replacement: str
    terraform_file: str

    def to_dict(self) -> dict:
        return {
            "finding": self.finding,
            "root_cause_edge": {
                "source": self.root_cause_edge.source,
                "target": self.root_cause_edge.target,
                "relation": self.root_cause_edge.relation.value,
                "evidence": self.root_cause_edge.evidence,
            },
            "remove_actions": list(self.remove_actions),
            "replacement": self.replacement,
            "terraform_file": self.terraform_file,
        }


def generate(path: AttackPath) -> Remediation:
    dangerous = next((edge for edge in path.edges if edge.relation == EdgeType.CAN_PASS_ROLE), None)
    if dangerous is None:
        raise ValueError("no deterministic remediation available for this path")
    return Remediation(
        finding="Low-trust workload role can pass a privileged execution role",
        root_cause_edge=dangerous,
        remove_actions=("iam:PassRole", "lambda:CreateFunction"),
        replacement="Remove PassRole and function-creation permissions from the low-trust role.",
        terraform_file="infrastructure/terraform/fixed.tfvars",
    )


def remediated_policy_check(edge: Edge) -> tuple[bool, str | None]:
    if edge.relation == EdgeType.CAN_PASS_ROLE:
        return False, "iam:PassRole denied by remediated least-privilege policy"
    return True, None


def vulnerable_policy_check(edge: Edge) -> tuple[bool, str | None]:
    return True, None

