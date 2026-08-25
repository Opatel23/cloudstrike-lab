from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cloudstrike.safety import LabManifest


ALLOWED_EVENTS = {"AssumeRole", "CreateFunction20150331", "Invoke20150331", "GetSecretValue"}


def ingest_cloudtrail(path: str | Path, manifest: LabManifest) -> list[dict[str, Any]]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    records = raw if isinstance(raw, list) else raw.get("Records", [])
    accepted = []
    for record in records:
        if record.get("eventName") not in ALLOWED_EVENTS:
            continue
        if str(record.get("recipientAccountId", "")) != manifest.account_id:
            continue
        region = record.get("awsRegion")
        if region and region != manifest.region:
            continue
        params = dict(record.get("requestParameters") or {})
        identifiers = " ".join(str(value) for value in params.values())
        if "cloudstrike-lab" not in identifiers and record.get("eventName") != "AssumeRole":
            continue
        params.pop("secretString", None)
        params.pop("clientContext", None)
        accepted.append({
            "event_id": record.get("eventID"),
            "event_time": record.get("eventTime"),
            "event_name": record.get("eventName"),
            "event_source": record.get("eventSource"),
            "region": region,
            "account_id": record.get("recipientAccountId"),
            "request_parameters": params,
            "error_code": record.get("errorCode"),
        })
    return accepted
