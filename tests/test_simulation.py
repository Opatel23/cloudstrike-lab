import unittest
from pathlib import Path

from cloudstrike.discovery import load_inventory
from cloudstrike.graph import AttackGraph
from cloudstrike.remediation import remediated_policy_check, vulnerable_policy_check
from cloudstrike.simulation import ControlledSimulator

FIXTURE = Path(__file__).parents[1] / "scenarios" / "iam-passrole" / "inventory.json"


def path():
    inventory = load_inventory(FIXTURE)
    return inventory, AttackGraph(inventory).paths_to_critical("principal:compromised-app")[0]


class SimulationTests(unittest.TestCase):
    def test_vulnerable_chain_succeeds(self):
        inventory, attack_path = path()
        result = ControlledSimulator(inventory.lab_id, vulnerable_policy_check).run(attack_path)
        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.reached, "secret:crown-jewel")
        self.assertEqual(len(result.events), 3)
        self.assertNotIn("PassRole", [event.event_name for event in result.events])
        create = result.events[1]
        self.assertEqual(create.event_name, "CreateFunction20150331")
        self.assertEqual(create.actor, "role:app")
        self.assertEqual(create.request_parameters["role"], "role:lambda-admin")

    def test_remediation_blocks_replay_at_passrole(self):
        inventory, attack_path = path()
        result = ControlledSimulator(inventory.lab_id, remediated_policy_check).run(attack_path)
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.stopped_at, 2)
        self.assertEqual(result.events[-1].event_name, "CreateFunction20150331")
        self.assertEqual(result.events[-1].authorization_action, "iam:PassRole")
        self.assertFalse(result.events[-1].allowed)

    def test_simulator_refuses_non_lab_environment(self):
        with self.assertRaisesRegex(ValueError, "refusing simulation"):
            ControlledSimulator("production", vulnerable_policy_check)

    def test_passrole_never_appears_as_cloudtrail_event(self):
        inventory, attack_path = path()
        for check in (vulnerable_policy_check, remediated_policy_check):
            result = ControlledSimulator(inventory.lab_id, check).run(attack_path)
            self.assertNotIn("PassRole", [event.event_name for event in result.events])

