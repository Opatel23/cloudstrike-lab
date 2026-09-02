import unittest
from pathlib import Path

from cloudstrike.discovery import load_inventory
from cloudstrike.graph import AttackGraph

FIXTURE = Path(__file__).parents[1] / "scenarios" / "iam-passrole" / "inventory.json"


class GraphTests(unittest.TestCase):
    def test_graph_finds_complete_chain(self):
        inventory = load_inventory(FIXTURE)
        path = AttackGraph(inventory).paths_to_critical("principal:compromised-app")[0]
        self.assertEqual(path.length, 4)
        self.assertEqual(path.nodes[-1], "secret:crown-jewel")
        self.assertEqual(path.nodes[2], "capability:pass-lambda-admin")
        self.assertEqual(
            [edge.relation.value for edge in path.edges],
            ["CAN_ASSUME", "CAN_PASS_ROLE", "CAN_CREATE_FUNCTION", "CAN_READ"],
        )
        self.assertEqual(path.edges[2].actor, "role:app")

