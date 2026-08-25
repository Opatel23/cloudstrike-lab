from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class EdgeType(StrEnum):
    CAN_ASSUME = "CAN_ASSUME"
    CAN_PASS_ROLE = "CAN_PASS_ROLE"
    CAN_CREATE_FUNCTION = "CAN_CREATE_FUNCTION"
    EXECUTES_AS = "EXECUTES_AS"
    CAN_READ = "CAN_READ"


@dataclass(frozen=True)
class Node:
    id: str
    kind: str
    name: str
    trust: str = "unknown"
    critical: bool = False
    tags: dict[str, str] = field(default_factory=dict, compare=False, hash=False)


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    relation: EdgeType
    evidence: str
    actions: tuple[str, ...] = ()
    actor: str | None = None
    parameters: dict[str, str] = field(default_factory=dict, compare=False, hash=False)


@dataclass
class Inventory:
    nodes: list[Node]
    edges: list[Edge]
    lab_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "lab_id": self.lab_id,
            "nodes": [asdict(node) for node in self.nodes],
            "edges": [asdict(edge) for edge in self.edges],
        }


@dataclass(frozen=True)
class AttackPath:
    nodes: tuple[str, ...]
    edges: tuple[Edge, ...]

    @property
    def length(self) -> int:
        return len(self.edges)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": list(self.nodes),
            "length": self.length,
            "steps": [
                {
                    "source": edge.source,
                    "relation": edge.relation.value,
                    "target": edge.target,
                    "evidence": edge.evidence,
                    "actions": list(edge.actions),
                    "actor": edge.actor or edge.source,
                    "parameters": edge.parameters,
                }
                for edge in self.edges
            ],
        }
