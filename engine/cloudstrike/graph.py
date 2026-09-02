from __future__ import annotations

from collections import defaultdict, deque

from cloudstrike.model import AttackPath, Edge, Inventory


class AttackGraph:
    """Small dependency-free directed graph; replaceable with NetworkX later."""

    def __init__(self, inventory: Inventory):
        self.inventory = inventory
        self.nodes = {node.id: node for node in inventory.nodes}
        self.outgoing: dict[str, list[Edge]] = defaultdict(list)
        for edge in inventory.edges:
            if edge.source not in self.nodes or edge.target not in self.nodes:
                raise ValueError(f"edge references unknown node: {edge}")
            self.outgoing[edge.source].append(edge)

    def shortest_path(self, start: str, target: str) -> AttackPath | None:
        if start not in self.nodes or target not in self.nodes:
            raise KeyError("start and target must be known graph nodes")
        queue = deque([(start, (), (start,))])
        visited = {start}
        while queue:
            current, edges, nodes = queue.popleft()
            if current == target:
                return AttackPath(nodes=nodes, edges=edges)
            for edge in self.outgoing[current]:
                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append((edge.target, edges + (edge,), nodes + (edge.target,)))
        return None

    def paths_to_critical(self, start: str) -> list[AttackPath]:
        paths = []
        for node in self.nodes.values():
            if node.critical and (path := self.shortest_path(start, node.id)):
                paths.append(path)
        return sorted(paths, key=lambda path: path.length)

