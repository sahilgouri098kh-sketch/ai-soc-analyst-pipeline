"""Analyze user-uploaded security logs without modifying the normal pipeline outputs."""

import csv
import io
import json
import re
from collections import Counter, defaultdict
from datetime import datetime

MAX_FILE_BYTES = 10 * 1024 * 1024
SUPPORTED_EXTENSIONS = {".log", ".txt", ".json", ".jsonl", ".ndjson", ".csv"}

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FAILED_SSH_RE = re.compile(
    r"(?:failed password|authentication failure|invalid user)\s+(?:for\s+)?(?:invalid user\s+)?(?P<user>[^\s]+).*?\bfrom\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)
ACCEPTED_SSH_RE = re.compile(
    r"accepted (?:password|publickey) for (?P<user>[^\s]+).*?\bfrom\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)


def _first(record, *keys):
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return value
    return None


def normalize_event(record):
    """Map common JSON/CSV field names to the pipeline's normalized schema."""
    event = dict(record)
    nested_raw = event.get("raw_event")
    if isinstance(nested_raw, dict):
        # Preserve normalized fields while making original vendor fields available
        # to detection rules (for example ports_scanned and query_length).
        event = {**nested_raw, **event}
    event_type = str(_first(
        event, "event_type", "event", "event_name", "type", "action", "category"
    ) or "").strip().lower().replace("-", "_").replace(" ", "_")
    message = str(_first(event, "message", "msg", "log", "description") or "")
    combined = f"{event_type} {message}".lower()

    source_ip = _first(
        event, "source_ip", "src_ip", "src", "client_ip", "remote_addr",
        "remote_ip", "client", "ip", "SourceIp", "SourceAddress"
    )
    destination_ip = _first(
        event, "destination_ip", "dest_ip", "dst_ip", "dst", "server_ip",
        "DestinationIp", "DestinationAddress"
    )
    timestamp = _first(event, "timestamp", "@timestamp", "time", "datetime", "date")
    username = _first(event, "username", "user", "user_name", "account", "User")
    status = str(_first(event, "status", "result", "outcome", "action_result") or "").lower()

    if not event_type:
        if "failed password" in combined or "authentication failure" in combined or "invalid user" in combined:
            event_type = "ssh_failed_login"
            status = "failed"
        elif "accepted password" in combined or "accepted publickey" in combined:
            event_type = "ssh_login"
            status = "success"
        elif "port scan" in combined or "ports_scanned" in event:
            event_type = "port_scan"
        elif "dns" in combined or "query_length" in event:
            event_type = "dns_query"
        elif "ssh" in combined or "sshd" in combined:
            event_type = "ssh_event"

    if any(term in event_type for term in ("failed_login", "login_failed", "authentication_failure")):
        event_type = "ssh_failed_login"
        status = "failed"
    elif event_type in {"login_success", "successful_login", "ssh_success"}:
        event_type = "ssh_login"
        status = "success"

    # Extract source IP and user from common Linux auth log messages.
    if not source_ip:
        match = FAILED_SSH_RE.search(message) or ACCEPTED_SSH_RE.search(message)
        if match:
            source_ip = match.group("ip")
            username = username or match.group("user")

    if not source_ip:
        ips = IPV4_RE.findall(message)
        if ips:
            source_ip = ips[0]

    raw = dict(event)
    if message and "query_length" not in raw:
        raw["message"] = message

    # Translate common field variants for existing detection rules.
    ports_scanned = _first(event, "ports_scanned", "port_count", "ports_count", "unique_ports")
    if ports_scanned is not None:
        try:
            raw["ports_scanned"] = int(ports_scanned)
        except (TypeError, ValueError):
            pass

    query_length = _first(event, "query_length", "dns_query_length")
    query = _first(event, "query", "dns_query", "question")
    if query_length is not None:
        try:
            raw["query_length"] = int(query_length)
        except (TypeError, ValueError):
            pass
    elif query is not None:
        raw["query_length"] = len(str(query))
    record_type = _first(event, "record_type", "dns_type", "query_type", "qtype")
    if record_type:
        raw["record_type"] = str(record_type).upper()
    elif event_type == "dns_query" and raw.get("query_length", 0) > 50:
        raw["record_type"] = "TXT"

    raw["event_type"] = event_type
    raw["status"] = status
    raw["source_ip"] = source_ip
    raw["destination_ip"] = destination_ip
    raw["timestamp"] = timestamp

    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": username,
        "status": status,
        "raw_event": raw,
    }


def _parse_linux_auth_line(line):
    match = FAILED_SSH_RE.search(line)
    if match:
        return {
            "timestamp": line[:15],
            "event_type": "ssh_failed_login",
            "source_ip": match.group("ip"),
            "username": match.group("user"),
            "status": "failed",
            "message": line,
        }
    match = ACCEPTED_SSH_RE.search(line)
    if match:
        return {
            "timestamp": line[:15],
            "event_type": "ssh_login",
            "source_ip": match.group("ip"),
            "username": match.group("user"),
            "status": "success",
            "message": line,
        }
    return None


def parse_uploaded_file(filename, content):
    """Parse supported JSON, JSONL, CSV, or common Linux auth text logs."""
    from pathlib import Path

    suffix = Path(filename).suffix.lower()
    if suffix not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            "Unsupported file type. Upload .log, .txt, .json, .jsonl, .ndjson, or .csv."
        )
    if len(content) > MAX_FILE_BYTES:
        raise ValueError("File exceeds the 10 MB upload limit.")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("The file must be UTF-8 text.") from exc

    records = []
    errors = 0
    if suffix == ".csv":
        try:
            records = list(csv.DictReader(io.StringIO(text)))
        except csv.Error as exc:
            raise ValueError(f"Could not parse CSV: {exc}") from exc
    elif suffix == ".json":
        try:
            obj = json.loads(text)
            if isinstance(obj, list):
                records = [item for item in obj if isinstance(item, dict)]
                errors = len(obj) - len(records)
            elif isinstance(obj, dict):
                # Common wrappers: {"events": [...]} or {"logs": [...]}
                nested = obj.get("events", obj.get("logs"))
                if isinstance(nested, list):
                    records = [item for item in nested if isinstance(item, dict)]
                    errors = len(nested) - len(records)
                else:
                    records = [obj]
            else:
                errors = 1
        except json.JSONDecodeError:
            # Some files named .json actually contain one JSON object per line.
            for line in text.splitlines():
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        records.append(obj)
                    else:
                        errors += 1
                except json.JSONDecodeError:
                    errors += 1
    elif suffix in {".jsonl", ".ndjson"}:
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(obj)
                else:
                    errors += 1
            except json.JSONDecodeError:
                errors += 1
    else:
        # .log/.txt: JSON-lines where possible, otherwise Linux auth text.
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(obj)
                else:
                    errors += 1
            except json.JSONDecodeError:
                parsed = _parse_linux_auth_line(line)
                if parsed:
                    records.append(parsed)
                else:
                    errors += 1

    normalized = [normalize_event(record) for record in records]
    if not normalized:
        raise ValueError(
            "No readable events found. This version supports JSON/JSONL, CSV, "
            "and common Linux SSH authentication log lines."
        )
    return normalized, errors


def analyze_events(events, use_gemini=False):
    """Run supported detections and triage in memory; do not call external TI APIs."""
    from src.detection_engine import detect_port_scan, detect_dns_tunneling

    def local_triage(alert):
        alert_type = alert.get("alert_type", "Unknown")
        action_map = {
            "SSH Brute Force": [
                "Review failed authentication attempts and source host activity",
                "Check whether a successful login followed the failures",
                "Validate the targeted account with the system owner",
            ],
            "Port Scan": [
                "Review connections to the scanned ports",
                "Determine whether the source host is authorized",
                "Check for related activity against other hosts",
            ],
            "Possible DNS Tunneling": [
                "Inspect DNS query patterns and query lengths",
                "Review DNS resolver and endpoint telemetry",
                "Correlate with other outbound connections",
            ],
        }
        return {
            "alert_id": alert.get("alert_id"),
            "severity": alert.get("severity", "Medium"),
            "verdict": "Needs Investigation",
            "confidence": 0.6,
            "attack_type": alert_type,
            "mitre_technique": alert.get("mitre_technique"),
            "source_ip": alert.get("source_ip"),
            "destination_ip": alert.get("destination_ip"),
            "event_count": alert.get("event_count", 1),
            "threat_intelligence": alert.get("threat_intelligence", {}),
            "reasoning_summary": (
                f"Detection rule matched {alert_type}. This is heuristic evidence; "
                "review the underlying log events before making a decision."
            ),
            "recommended_actions": action_map.get(
                alert_type, ["Review the alert and validate the underlying events"]
            ),
            "triage_provider": "rules_fallback",
        }

    failed_counts = Counter()
    for event in events:
        if event.get("event_type") == "ssh_failed_login" and event.get("status") == "failed":
            if event.get("source_ip"):
                failed_counts[event["source_ip"]] += 1

    raw_alerts = []
    for event in events:
        for detection in (detect_port_scan(event), detect_dns_tunneling(event)):
            if detection:
                raw_alerts.append(detection)

    for source_ip, count in failed_counts.items():
        if count >= 5:
            related = [e for e in events if e.get("source_ip") == source_ip
                       and e.get("event_type") == "ssh_failed_login"
                       and e.get("status") == "failed"]
            raw_alerts.append({
                "alert_type": "SSH Brute Force",
                "severity": "High",
                "source_ip": source_ip,
                "destination_ip": next((e.get("destination_ip") for e in related if e.get("destination_ip")), None),
                "timestamp": related[0].get("timestamp"),
                "description": f"Detected {count} failed SSH login attempts from {source_ip}",
                "mitre_technique": "T1110.001",
                "events": related,
            })

    grouped = defaultdict(list)
    for alert in raw_alerts:
        key = (alert.get("alert_type"), alert.get("source_ip"), alert.get("destination_ip"))
        grouped[key].append(alert)

    triaged = []
    for index, (key, items) in enumerate(grouped.items(), start=1):
        first = items[0]
        evidence = first.get("events")
        if not evidence:
            evidence = [
                event for event in events
                if (not first.get("source_ip") or event.get("source_ip") == first.get("source_ip"))
                and (not first.get("destination_ip") or event.get("destination_ip") == first.get("destination_ip"))
            ][:20]
        alert = {
            "alert_id": f"UPLOAD-{index:04d}",
            "alert_type": first.get("alert_type", "Unknown"),
            "severity": first.get("severity", "Medium"),
            "source_ip": first.get("source_ip"),
            "destination_ip": first.get("destination_ip"),
            "mitre_technique": first.get("mitre_technique"),
            "first_seen": items[0].get("timestamp"),
            "last_seen": items[-1].get("timestamp"),
            "event_count": sum(1 for event in events if first.get("source_ip") and event.get("source_ip") == first.get("source_ip")) or len(items),
            "description": first.get("description", ""),
            "events": evidence,
            "threat_intelligence": {
                "status": "skipped",
                "reason": "Automatic external lookups are disabled for uploaded logs to protect log privacy.",
            },
        }
        if use_gemini:
            try:
                import os
                from dotenv import load_dotenv
                from google import genai
                from src.ai_triage import triage_alert
                load_dotenv()
                api_key = os.getenv("GEMINI_API_KEY")
                if not api_key:
                    raise RuntimeError("GEMINI_API_KEY is not configured")
                client = genai.Client(api_key=api_key)
                result = triage_alert(alert, client)
            except Exception as exc:
                result = local_triage(alert)
                result["triage_note"] = f"Gemini unavailable ({type(exc).__name__}); rule-based triage used."
        else:
            result = local_triage(alert)
            result["triage_note"] = "Gemini not called; uploaded log evidence stayed local."
        # Keep context needed by the dashboard/report and make privacy state explicit.
        result["alert_type"] = alert["alert_type"]
        result["description"] = alert["description"]
        result["first_seen"] = alert["first_seen"]
        result["last_seen"] = alert["last_seen"]
        result["events"] = evidence
        result["threat_intelligence"] = alert["threat_intelligence"]
        triaged.append(result)

    return triaged
