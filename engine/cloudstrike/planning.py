from __future__ import annotations

from dataclasses import asdict, dataclass

from cloudstrike.graph import AttackGraph
from cloudstrike.model import Inventory
from cloudstrike.safety import LabManifest


@dataclass(frozen=True)
class PlannedAction:
    order: int
    api_action: str
    actor: str
    target: str
    mode: str = "DRY_RUN"


def build_dry_run(inventory: Inventory, manifest: LabManifest) -> dict:
    paths = AttackGraph(inventory).paths_to_critical("principal:compromised-app")
    path = paths[0] if paths else None
    actions = []
    if path:
        order = 1
        for edge in path.edges:
            for action in edge.actions:
                if action == "iam:PassRole":
                    continue  # prerequisite, not an API call
                actions.append(PlannedAction(order, action, edge.actor or edge.source, edge.target))
                order += 1
    return {
        "mode": "DRY_RUN",
        "lab_id": manifest.lab_id,
        "account_id": manifest.account_id,
        "region": manifest.region,
        "path_found": path is not None,
        "path": path.to_dict() if path else None,
        "planned_actions": [asdict(action) for action in actions],
        "executed_actions": 0,
    }

