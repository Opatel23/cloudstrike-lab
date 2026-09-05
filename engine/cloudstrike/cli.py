from __future__ import annotations

import argparse
import json
from pathlib import Path

from cloudstrike.cloudtrail import ingest_cloudtrail
from cloudstrike.discovery import AwsLabDiscovery, boto3_client_factory
from cloudstrike.planning import build_dry_run
from cloudstrike.report import run_demo, write_report
from cloudstrike.safety import LabManifest, SafetyViolation
from cloudstrike.verification import ReportVerificationError, verify_report_file


def _fixture() -> Path:
    return Path(__file__).resolve().parents[2] / "scenarios" / "iam-passrole" / "inventory.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cloudstrike")
    subparsers = parser.add_subparsers(dest="command", required=True)
    demo = subparsers.add_parser("demo", help="run safe local before/after validation")
    demo.add_argument("--fixture", type=Path, default=_fixture())
    demo.add_argument("--output", type=Path, default=Path("outputs/demo-report.json"))
    aws_plan = subparsers.add_parser("aws-plan", help="read AWS lab state and emit a non-executing action plan")
    aws_plan.add_argument("--manifest", type=Path, required=True, help="terraform output -json file")
    aws_plan.add_argument("--output", type=Path, default=Path("outputs/aws-dry-run.json"))
    trail = subparsers.add_parser("ingest-cloudtrail", help="filter and redact exported lab CloudTrail JSON")
    trail.add_argument("--manifest", type=Path, required=True)
    trail.add_argument("--input", type=Path, required=True)
    trail.add_argument("--output", type=Path, default=Path("outputs/cloudtrail-events.json"))
    verify = subparsers.add_parser("verify-report", help="validate a CloudStrike evidence report")
    verify.add_argument("report", type=Path)
    args = parser.parse_args(argv)

    if args.command == "demo":
        report = run_demo(args.fixture)
        write_report(report, args.output)
        summary = report["summary"]
        print(f"Attack path before remediation: {summary['before']}")
        print(f"Attack replay after remediation: {summary['after']}")
        print(f"Blocked at step: {summary['blocked_at_step']}")
        print(f"Reason: {summary['blocked_reason']}")
        print(f"Report: {args.output.resolve()}")
        return 0 if summary["before"] == "SUCCESS" and summary["after"] == "BLOCKED" else 1
    if args.command == "aws-plan":
        try:
            manifest = LabManifest.from_terraform_output(args.manifest)
            inventory = AwsLabDiscovery(manifest, boto3_client_factory).discover()
            payload = build_dry_run(inventory, manifest)
        except (SafetyViolation, RuntimeError) as exc:
            parser.error(str(exc))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"Dry run only: {len(payload['planned_actions'])} API actions planned, 0 executed")
        print(f"Plan: {args.output.resolve()}")
        return 0
    if args.command == "ingest-cloudtrail":
        try:
            manifest = LabManifest.from_terraform_output(args.manifest)
            events = ingest_cloudtrail(args.input, manifest)
        except SafetyViolation as exc:
            parser.error(str(exc))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({"events": events}, indent=2) + "\n", encoding="utf-8")
        print(f"Accepted {len(events)} lab-scoped CloudTrail events")
        print(f"Output: {args.output.resolve()}")
        return 0
    if args.command == "verify-report":
        try:
            result = verify_report_file(args.report)
        except (OSError, ReportVerificationError) as exc:
            parser.error(str(exc))
        print(f"Report verified: {result.path.resolve()}")
        print(f"Lab: {result.lab_id}")
        print(f"Attack path edges: {result.path_length}")
        print(f"Detections: {result.detections}")
        print(f"Blocked at step: {result.blocked_at_step}")
        print(f"SHA-256: {result.digest}")
        return 0
    return 2
