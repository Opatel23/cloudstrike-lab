from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from itertools import count
from pathlib import Path

from cloudstrike.detection import detect
from cloudstrike.discovery import load_inventory
from cloudstrike.graph import AttackGraph
from cloudstrike.remediation import generate, remediated_policy_check, vulnerable_policy_check
from cloudstrike.simulation import ControlledSimulator

DEMO_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


def _demo_clock():
    ticks = count()
    return lambda: DEMO_EPOCH + timedelta(seconds=next(ticks))


def run_demo(fixture: str | Path) -> dict:
    inventory = load_inventory(fixture)
    graph = AttackGraph(inventory)
    paths = graph.paths_to_critical("principal:compromised-app")
    if not paths:
        raise RuntimeError("no path from compromised application to a critical asset")
    path = paths[0]
    before = ControlledSimulator(inventory.lab_id, vulnerable_policy_check, _demo_clock()).run(path)
    remediation = generate(path)
    after = ControlledSimulator(inventory.lab_id, remediated_policy_check, _demo_clock()).run(path)
    detections = detect(before.events)
    return {
        "schema_version": "1.0",
        "provenance": {
            "generator": "cloudstrike-engine",
            "mode": "controlled-local-simulation",
            "fixture": Path(fixture).name,
            "live_aws_actions": 0,
        },
        "lab_id": inventory.lab_id,
        "inventory": inventory.to_dict(),
        "summary": {
            "before": before.status,
            "after": after.status,
            "critical_asset": path.nodes[-1],
            "path_length": path.length,
            "blocked_at_step": after.stopped_at,
            "blocked_reason": after.reason,
            "detections_triggered": len(detections),
        },
        "attack_path": path.to_dict(),
        "before": before.to_dict(),
        "detections": [
            {
                "rule_id": item.rule_id,
                "title": item.title,
                "severity": item.severity,
                "mitre_techniques": list(item.mitre_techniques),
                "event": item.event,
            }
            for item in detections
        ],
        "remediation": remediation.to_dict(),
        "after": after.to_dict(),
    }


def write_report(report: dict, output: str | Path) -> None:
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

