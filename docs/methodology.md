# Evaluation Methodology

Each scenario is evaluated as an experiment with a frozen environment manifest and expected path.

## Procedure

1. Deploy the vulnerable configuration in a fresh sandbox.
2. Record Terraform outputs and caller account ID.
3. Discover resources and construct the graph without reading Terraform policy intent.
4. Compare the discovered path to the scenario's expected path.
5. Run the allowlisted simulation and ingest real CloudTrail events.
6. Evaluate local and Sigma detections.
7. Generate and review the deterministic remediation.
8. Apply the fixed configuration and rediscover the environment.
9. Replay the same attack plan and record the blocking edge.
10. Destroy the environment and verify no tagged resources remain.

## Metrics

- Path precision: validated discovered paths / simulated discovered paths.
- Path recall: expected viable paths discovered / expected viable paths.
- Discovery time and graph-search time.
- Validation success rate and false-positive paths.
- Detection coverage by path step and mean detection delay.
- Remediation success rate and attack-path count reduction.
- Residual critical paths after remediation.
- Estimated scenario cost and total lab lifetime.

## Evidence rules

Synthetic local events prove orchestration logic only. A live result may be labeled `validated` only when the report includes the matching CloudTrail event IDs, account ID, region, resource manifest hash, and timestamps. Secret values are always redacted.

