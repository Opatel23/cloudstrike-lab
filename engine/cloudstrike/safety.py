from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SafetyViolation(RuntimeError):
    """Raised when a live adapter cannot prove it is operating inside the lab."""


def _value(outputs: dict[str, Any], key: str) -> Any:
    item = outputs.get(key)
    if not isinstance(item, dict) or "value" not in item:
        raise SafetyViolation(f"Terraform output is missing required value: {key}")
    return item["value"]


@dataclass(frozen=True)
class LabManifest:
    lab_id: str
    account_id: str
    region: str
    app_role_arn: str
    privileged_role_arn: str
    secret_arn: str

    @classmethod
    def from_terraform_output(cls, path: str | Path) -> LabManifest:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        manifest = cls(
            lab_id=str(_value(raw, "lab_id")),
            account_id=str(_value(raw, "account_id")),
            region=str(_value(raw, "aws_region")),
            app_role_arn=str(_value(raw, "app_role_arn")),
            privileged_role_arn=str(_value(raw, "privileged_role_arn")),
            secret_arn=str(_value(raw, "secret_arn")),
        )
        manifest.validate()
        return manifest

    def validate(self) -> None:
        if not self.lab_id.startswith("cloudstrike-lab-"):
            raise SafetyViolation("lab_id must start with cloudstrike-lab-")
        if not (self.account_id.isdigit() and len(self.account_id) == 12):
            raise SafetyViolation("account_id must be a 12-digit AWS account ID")
        for label, arn in {
            "app role": self.app_role_arn,
            "privileged role": self.privileged_role_arn,
            "secret": self.secret_arn,
        }.items():
            if not arn.startswith("arn:aws:") or f":{self.account_id}:" not in arn:
                raise SafetyViolation(f"{label} ARN is not scoped to the manifest account")
            if "cloudstrike-lab" not in arn:
                raise SafetyViolation(f"{label} ARN is not a CloudStrike lab resource")

    def assert_caller(self, caller_account_id: str) -> None:
        if caller_account_id != self.account_id:
            raise SafetyViolation(
                f"AWS caller account {caller_account_id} does not match lab account {self.account_id}"
            )

    @property
    def allowed_arns(self) -> frozenset[str]:
        return frozenset({self.app_role_arn, self.privileged_role_arn, self.secret_arn})


def require_lab_tags(tags: list[dict[str, str]] | dict[str, str], lab_id: str) -> None:
    normalized = tags if isinstance(tags, dict) else {tag["Key"]: tag["Value"] for tag in tags}
    if normalized.get("Project") != "cloudstrike-lab" or normalized.get("LabID") != lab_id:
        raise SafetyViolation("resource is missing the required CloudStrike lab tags")


