# Threat Model

## Assets to protect

- AWS accounts outside the dedicated sandbox.
- Credentials used to deploy or inspect the lab.
- CloudTrail integrity and the local report pipeline.
- Real secrets and data that must never enter the scenario.

## Trust boundaries

Terraform crosses from local code into AWS. Discovery reads AWS control-plane state. A future live simulator will make narrowly scoped control-plane calls. CloudTrail returns evidence from AWS to the analysis engine. Each boundary requires explicit account and resource identity checks.

## Primary failure modes

- Operator authenticates to the wrong AWS account.
- A broad IAM policy unintentionally affects a non-lab role.
- Simulator accepts arbitrary ARNs, actions, or scenario definitions.
- Sensitive values leak through console output or generated reports.
- Lab resources accrue cost after the demonstration.
- Synthetic telemetry is mistaken for actual CloudTrail evidence.

## Controls in this milestone

- Vulnerable policy is disabled by default.
- Terraform requires explicit isolated-sandbox acknowledgement.
- Resources are prefixed and tagged; the secret contains fake data.
- IAM resources are scoped to exact lab ARNs where AWS permits it.
- The local simulator refuses non-lab IDs and has no generic command execution.
- Reports contain resource identifiers and outcomes, never secret content.
- The README includes teardown as part of the standard workflow.

## Required controls before live simulation

Add a second acknowledgement at execution time, caller-account allowlisting, Terraform output manifest signing/hash verification, resource tag checks immediately before every action, maximum-cost/time bounds, read-only default mode, CloudTrail health verification, and a cleanup command that reports any surviving tagged resource.

## Explicit non-goals

- Scanning or simulating against third-party, employer, production, or shared accounts.
- Credential theft, persistence, evasion, data exfiltration, or destructive actions.
- Arbitrary plugin/script execution supplied by scenario files.
- Claiming GuardDuty or SIEM detection without ingesting their real output.

