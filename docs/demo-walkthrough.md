# CloudStrike demo walkthrough

## Start

Install Python 3.11+, Node.js 22.13+, and the dashboard dependencies described in the README. Run `./run-demo.ps1` from PowerShell and open http://localhost:3000.

## Show the attack path

Select **Before fix**. Follow the application role through its PassRole grant and Lambda creation capability to the demo secret. Explain that PassRole is an authorization check within workload creation, not a separate CloudTrail API event.

The engine uses a bundled inventory and synthetic telemetry. This demonstrates the graph and validation workflow; it does not establish that an attack was executed in AWS.

## Explain the evidence

Inspect the detection timeline and the underlying events. Describe which action triggered each detection, the actor, and the target. The JSON report contains the same evidence displayed in the dashboard.

## Show the fix

Select **Apply fix & replay**. The replay stops at edge 2 because the remediated policy denies `iam:PassRole`. Review the removed permissions and the Terraform configuration for the fixed policy.

The dashboard displays the engine's before/after report. Clicking the button does not deploy infrastructure or change an AWS policy.

## Verify the report

```powershell
$env:PYTHONPATH = "$PWD/engine"
python -m cloudstrike verify-report outputs/demo-report.json
```

The verifier checks internal consistency and prints the file's SHA-256 digest. It is not a digital signature or proof of live cloud execution.

## Discuss the limits

- One scenario is implemented end to end locally.
- AWS inventory discovery and CloudTrail ingestion need a dedicated sandbox acceptance run.
- Detection counts in the demo are not production accuracy or coverage measurements.
- The repository includes infrastructure definitions, but live exploitation is not enabled.
