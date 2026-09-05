# CloudStrike Lab

[![CI](https://github.com/Opatel23/cloudstrike-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/Opatel23/cloudstrike-lab/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Terraform](https://img.shields.io/badge/Terraform-AWS%20lab-844FBA?logo=terraform&logoColor=white)
![Safety](https://img.shields.io/badge/scope-authorized%20sandbox-2ea44f)

CloudStrike Lab is a controlled AWS breach-simulation platform built around attack chains, not isolated findings. The current MVP proves one full vertical slice:

```text
Compromised app → app role → iam:PassRole → privileged Lambda → demo secret
        │                                                   │
        └──────── vulnerable replay: SUCCESS ───────────────┘
                            ↓ least-privilege remediation
                    fixed replay: BLOCKED at PassRole
```

The repository includes a deliberately vulnerable Terraform lab, a Python attack-graph engine, a safety-gated simulator, CloudTrail-shaped telemetry, ATT&CK-mapped detections, a deterministic remediation, and a machine-readable before/after proof. Identical local inputs produce byte-for-byte identical reports, including synthetic event timestamps.

> **Portfolio note:** the default experience is a deterministic local simulation. It does not call AWS, deploy infrastructure, or execute live exploitation. AWS-specific commands fail closed unless a dedicated sandbox manifest, matching account, and required lab tags are present.

## Current status

The local MVP is complete and release-tested. It includes the report-driven dashboard, Terraform lab definition, graph and remediation engine, fail-closed AWS inventory discovery, a zero-execution AWS dry-run plan, and scoped CloudTrail ingestion with sensitive-field redaction. The default demo remains fixture-backed, free, repeatable, and unable to mutate AWS.

Live AWS exploitation is intentionally not enabled. The next controlled milestone is validating discovery and telemetry in a dedicated sandbox account, then implementing an explicitly allowlisted executor for the single demo chain.

Verified behavior:

```text
Attack path before remediation: SUCCESS
Attack replay after remediation: BLOCKED
Blocked at step: 2
Reason: iam:PassRole denied by remediated least-privilege policy
```

See the generated [demo report](outputs/demo-report.json).

## Run locally

Python 3.11+ is sufficient; the engine has no runtime dependencies.

```powershell
$env:PYTHONPATH = "$PWD/engine"
python -m cloudstrike demo --output outputs/demo-report.json
python -m cloudstrike verify-report outputs/demo-report.json
python -m unittest discover -s tests -v
```

Or install in editable mode:

```powershell
python -m pip install -e .
cloudstrike demo
```

## Open the dashboard

From the repository root, use the one-command Windows launcher:

```powershell
.\run-demo.ps1
```

It generates the report, copies that exact artifact into the dashboard, starts the local site in the background, and waits until the health check passes. If the dashboard is already running, it refreshes the report and tells you to reload the page. You can close PowerShell after it says the site is ready.

For foreground development with live logs:

```powershell
.\run-demo.ps1 -Foreground
```

To run the full engine verification without starting the server:

```powershell
.\run-demo.ps1 -VerifyOnly
```

The interactive dashboard lives in `dashboard/`. To start it manually instead:

```powershell
cd dashboard
pnpm install
pnpm dev
```

Open `http://localhost:3000`. Switch between **Before fix** and **After fix**, or press **Apply fix & replay**, to inspect the path, blocking edge, detection timeline, and Terraform policy change.

The Python engine is the source of truth. The dashboard fetches `dashboard/public/demo-report.json`, which the launcher refreshes from `outputs/demo-report.json` on every run.

Before publishing or sharing evidence, validate the report contract:

```powershell
$env:PYTHONPATH = "$PWD/engine"
python -m cloudstrike verify-report outputs/demo-report.json
```

The verifier rejects unsafe provenance, non-CloudStrike lab IDs, mismatched summary fields, path steps that are absent from inventory, replay events from another lab, and detections that do not map back to the vulnerable replay. It also prints a SHA-256 digest for the exact JSON artifact you are sharing.

## Where to edit or add code

- Python engine: `engine/cloudstrike/`
- Scenario definitions: `scenarios/`
- AWS infrastructure: `infrastructure/terraform/`
- Detection rules: `detections/sigma/`
- Dashboard: `dashboard/app/`
- Automated tests: `tests/`

Use VS Code, PyCharm, or Codex to open the repository root. Do not paste the project into the AWS console. AWS receives infrastructure only through Terraform after you authenticate to a dedicated sandbox account.

## AWS lab

Only deploy in a dedicated sandbox AWS account. Review the plan, budget alarms, and IAM policies first.

```powershell
cd infrastructure/terraform
Copy-Item vulnerable.tfvars.example vulnerable.tfvars
# Replace lab_owner, then authenticate to a dedicated sandbox account.
terraform init
terraform plan -var-file vulnerable.tfvars
terraform apply -var-file vulnerable.tfvars
terraform output -json | Set-Content -Encoding utf8 ..\..\work\terraform-output.json
```

The lab requires an explicit sandbox acknowledgement, tags every resource, constrains names to `cloudstrike-lab-*`, stores only fake data, blocks public access to its trail bucket, and defaults the vulnerable policy to off.

After deployment, inspect the real account without executing attack actions:

```powershell
$env:PYTHONPATH = "$PWD\engine"
python -m cloudstrike aws-plan --manifest work\terraform-output.json --output outputs\aws-plan.json
```

The command checks the caller account before resource discovery, requires the Terraform manifest and lab tags, and writes a dry-run plan with `executed_actions: 0`.

To normalize a downloaded CloudTrail event file:

```powershell
python -m cloudstrike ingest-cloudtrail --manifest work\terraform-output.json --input work\cloudtrail.json --output outputs\cloudtrail-events.json
```

Only events matching the lab account, region, and resource identifiers are retained. Sensitive request fields are redacted. See the [AWS sandbox runbook](docs/aws-sandbox-runbook.md) for the complete procedure.

To represent the deterministic fix:

```powershell
Copy-Item fixed.tfvars.example fixed.tfvars
terraform plan -var-file fixed.tfvars
terraform apply -var-file fixed.tfvars
```

Always clean up after a session:

```powershell
terraform destroy -var-file fixed.tfvars
```

## Repository map

```text
engine/cloudstrike/           graph, simulator, detection, remediation, CLI
scenarios/iam-passrole/       captured inventory for scenario 001
infrastructure/terraform/     vulnerable/fixed isolated AWS lab
detections/sigma/             portable detection content
tests/                        end-to-end and safety-gate tests
docs/                         architecture, threat model, methodology, roadmap
outputs/demo-report.json      reproducible before/after evidence
```

## Definition of done for scenario 001

- Terraform plan creates only tagged lab resources in a sandbox account.
- Live discovery reproduces the captured graph from AWS APIs.
- The simulator executes only allowlisted actions against matching lab tags/account ID.
- CloudTrail events are ingested from the lab trail rather than synthesized.
- The PassRole chain reaches only the fake demo secret in vulnerable state.
- Applying the fix removes the risky policy, and replay fails at the same step.
- The report records timings, detected events, false positives, and path reduction.

The local proof meets the graph/replay/remediation, AWS discovery safety, dry-run planning, and CloudTrail ingestion portions. A real sandbox acceptance run and allowlisted API executor remain deliberately separate from the completed local MVP.

## Safety

This is an authorized training lab, not a generic exploitation framework. Do not deploy into production, shared, employer, or third-party accounts. The simulator must remain tied to Terraform outputs, account allowlisting, lab tags, resource-name prefixes, a fixed action registry, and teardown instructions. See [Threat model](docs/threat-model.md).

## Roadmap

1. Run scenario 001 discovery and telemetry acceptance tests in a dedicated AWS sandbox.
2. Add an allowlisted, confirmation-gated AWS executor for this scenario only.
3. Add a small graph/dashboard API so live reports can stream into the UI.
4. Add scenarios only after scenario 001 passes its live acceptance test: metadata/role abuse, insecure trust, exposed storage, cross-role escalation.
5. Add experiment metrics for path precision, validation rate, time-to-discovery, detection coverage, and remediation success.
