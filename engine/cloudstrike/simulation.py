from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, ClassVar

from cloudstrike.model import AttackPath, Edge


@dataclass(frozen=True)
class SimulationEvent:
    timestamp: str
    event_name: str
    actor: str
    target: str
    relation: str
    allowed: bool
    lab_id: str
    error: str | None = None
    event_source: str = ""
    request_parameters: dict[str, Any] | None = None
    authorization_action: str | None = None


@dataclass
class SimulationResult:
    status: str
    reached: str | None
    stopped_at: int | None
    reason: str | None
    events: list[SimulationEvent]

    def to_dict(self) -> dict:
        return {**asdict(self), "events": [asdict(event) for event in self.events]}


class ControlledSimulator:
    """Replays graph edges only in an explicitly identified Terraform lab."""

    EVENT_METADATA: ClassVar[dict[str, tuple[str, str]]] = {
        "CAN_ASSUME": ("AssumeRole", "sts.amazonaws.com"),
        "CAN_CREATE_FUNCTION": ("CreateFunction20150331", "lambda.amazonaws.com"),
        "EXECUTES_AS": ("Invoke20150331", "lambda.amazonaws.com"),
        "CAN_READ": ("GetSecretValue", "secretsmanager.amazonaws.com"),
    }

    def __init__(self, lab_id: str, policy_check: Callable[[Edge], tuple[bool, str | None]]):
        if not lab_id.startswith("cloudstrike-lab-"):
            raise ValueError("refusing simulation outside a cloudstrike-lab-* environment")
        self.lab_id = lab_id
        self.policy_check = policy_check

    def run(self, path: AttackPath) -> SimulationResult:
        events: list[SimulationEvent] = []
        for index, edge in enumerate(path.edges, start=1):
            allowed, reason = self.policy_check(edge)
            if edge.relation.value == "CAN_PASS_ROLE":
                # PassRole is an IAM authorization check, not an AWS API event.
                # A denial is recorded on the attempted CreateFunction call.
                if allowed:
                    continue
                event_name, event_source = self.EVENT_METADATA["CAN_CREATE_FUNCTION"]
                events.append(
                    SimulationEvent(
                        timestamp=datetime.now(UTC).isoformat(),
                        event_name=event_name,
                        event_source=event_source,
                        actor=edge.actor or edge.source,
                        target=edge.target,
                        relation=edge.relation.value,
                        allowed=False,
                        lab_id=self.lab_id,
                        error=reason,
                        request_parameters={"role": edge.parameters.get("role", edge.target)},
                        authorization_action="iam:PassRole",
                    )
                )
                return SimulationResult("BLOCKED", None, index, reason, events)

            event_name, event_source = self.EVENT_METADATA[edge.relation.value]
            events.append(
                SimulationEvent(
                    timestamp=datetime.now(UTC).isoformat(),
                    event_name=event_name,
                    event_source=event_source,
                    actor=edge.actor or edge.source,
                    target=edge.target,
                    relation=edge.relation.value,
                    allowed=allowed,
                    lab_id=self.lab_id,
                    error=None if allowed else reason,
                    request_parameters=self._request_parameters(edge),
                )
            )
            if not allowed:
                return SimulationResult("BLOCKED", None, index, reason, events)
        return SimulationResult("SUCCESS", path.nodes[-1], None, None, events)

    @staticmethod
    def _request_parameters(edge: Edge) -> dict[str, Any]:
        if edge.relation.value == "CAN_CREATE_FUNCTION":
            return {
                "functionName": "cloudstrike-lab-controlled-simulator",
                "role": edge.parameters.get("role", edge.source),
            }
        if edge.relation.value == "CAN_READ":
            return {"secretId": edge.target}
        return {}

