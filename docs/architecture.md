# Architecture

## Vertical slice

The first scenario models a low-trust application identity that can pass a more privileged role while creating a lab-named Lambda function. The function's execution role can read one fake Secrets Manager value. The graph is meaningful because no single resource finding describes the complete impact.

```text
Terraform state/AWS APIs
        ↓
Inventory (typed nodes and evidence-backed edges)
        ↓
AttackGraph (shortest paths from untrusted origins to critical assets)
        ↓
ControlledSimulator (allowlisted lab actions only)
        ├── events → detector → ATT&CK mappings
        └── result → deterministic remediation rule
                              ↓
                       apply and replay
                              ↓
                    before/after report
```

## Components

- `model.py`: stable data contract for nodes, edges, inventory, and paths.
- `graph.py`: dependency-free directed graph and breadth-first path search. NetworkX can replace it when path constraints and multiple scenarios require it.
- `simulation.py`: action replay with an invariant that the lab ID starts with `cloudstrike-lab-`. The live adapter must add account, tag, ARN, and Terraform-state verification before making an AWS call.
- `detection.py`: local event evaluation and ATT&CK annotations. Sigma content is kept separately for SIEM portability.
- `remediation.py`: scenario-specific, deterministic root-cause selection. It does not use an LLM to invent IAM policy.
- `report.py`: orchestrates the before/fix/after proof and emits a versioned JSON artifact.

## Data contract

Every graph edge contains source, target, relationship, actions, and human-readable evidence. A path is only actionable when each edge can be validated by a simulator module. Discovery and execution remain separate: discovery may identify paths that the safety policy refuses to execute.

## Live adapter acceptance gates

Before live execution is added, it must verify all of the following independently:

1. Caller account ID equals the account captured at Terraform deployment.
2. Every target ARN exists in the Terraform output manifest.
3. Every target has `Project=cloudstrike-lab` and the expected `LabID` tag.
4. Every API operation appears in the scenario's immutable action registry.
5. Secret payloads are never written to reports or logs.
6. A dry-run/plan is shown before action and teardown is available.

