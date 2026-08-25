from __future__ import annotations

import json
from pathlib import Path

from cloudstrike.model import Edge, EdgeType, Inventory, Node


def load_inventory(path: str | Path) -> Inventory:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return Inventory(
        lab_id=raw["lab_id"],
        nodes=[Node(**node) for node in raw["nodes"]],
        edges=[
            Edge(
                source=edge["source"],
                target=edge["target"],
                relation=EdgeType(edge["relation"]),
                evidence=edge["evidence"],
                actions=tuple(edge.get("actions", [])),
                actor=edge.get("actor"),
                parameters=edge.get("parameters", {}),
            )
            for edge in raw["edges"]
        ],
    )
