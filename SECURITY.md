# Security Policy

## Scope

CloudStrike Lab is designed for local simulation and dedicated AWS sandbox accounts. Never deploy the vulnerable configuration into production, shared, employer, customer, or third-party environments.

## Reporting a vulnerability

Report credential exposure, unsafe defaults, authorization bypasses, or unintended AWS mutations privately to the repository owner. Do not include live credentials, sensitive account identifiers, or exploit evidence in a public issue.

## Safety invariants

- Live discovery must validate the AWS account against Terraform outputs before enumerating resources.
- AWS resources must match the lab manifest, required tags, region, and `cloudstrike-lab-*` naming boundary.
- Dry runs must report zero executed actions.
- Sensitive CloudTrail request fields must be redacted during ingestion.
- The default demo must remain fixture-backed and unable to mutate AWS.
- Any future executor must use a fixed action registry and explicit user confirmation.

Changes that weaken these controls will not be accepted.
