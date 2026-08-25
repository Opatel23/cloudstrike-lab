from __future__ import annotations

from dataclasses import asdict, dataclass

from cloudstrike.simulation import SimulationEvent


@dataclass(frozen=True)
class Detection:
    rule_id: str
    title: str
    severity: str
    mitre_techniques: tuple[str, ...]
    event: dict


def detect(events: list[SimulationEvent]) -> list[Detection]:
    detections = []
    for event in events:
        if event.allowed and event.event_name == "CreateFunction20150331":
            detections.append(
                Detection(
                    rule_id="CS-AWS-001",
                    title="Privileged lab function created with a passed execution role",
                    severity="high",
                    mitre_techniques=("T1098", "T1548"),
                    event=asdict(event),
                )
            )
        if event.allowed and event.event_name == "GetSecretValue":
            detections.append(
                Detection(
                    rule_id="CS-AWS-002",
                    title="Sensitive secret read by simulated attack principal",
                    severity="critical",
                    mitre_techniques=("T1552.005",),
                    event=asdict(event),
                )
            )
    return detections
