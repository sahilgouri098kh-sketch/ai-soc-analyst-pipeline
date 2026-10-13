import json
from pathlib import Path
from collections import Counter


INPUT_FILE = Path("data/processed/normalized_logs.jsonl")
OUTPUT_FILE = Path("alerts/raw/detection_alerts.jsonl")


def detect_port_scan(event):
    raw_event = event.get("raw_event", {})

    ports_scanned = raw_event.get("ports_scanned", 0)

    if ports_scanned > 100:
        return {
            "alert_type": "Port Scan",
            "severity": "High",
            "source_ip": event.get("source_ip"),
            "destination_ip": event.get("destination_ip"),
            "timestamp": event.get("timestamp"),
            "description": (
                f"Possible port scan detected: "
                f"{ports_scanned} ports scanned"
            ),
            "mitre_technique": "T1046"
        }

    return None


def detect_dns_tunneling(event):
    raw_event = event.get("raw_event", {})

    query_length = raw_event.get("query_length", 0)
    record_type = raw_event.get("record_type")

    if record_type == "TXT" and query_length > 50:
        return {
            "alert_type": "Possible DNS Tunneling",
            "severity": "High",
            "source_ip": event.get("source_ip"),
            "destination_ip": event.get("destination_ip"),
            "timestamp": event.get("timestamp"),
            "description": (
                f"Suspicious DNS query detected: "
                f"TXT record with query length {query_length}"
            ),
            "mitre_technique": "T1071.004"
        }

    return None


def detect_ssh_brute_force(events):
    failed_logins = Counter()

    for event in events:
        if (
            event.get("event_type") == "ssh_failed_login"
            and event.get("status") == "failed"
        ):
            source_ip = event.get("source_ip")

            if source_ip:
                failed_logins[source_ip] += 1

    alerts = []

    for source_ip, count in failed_logins.items():

        if count >= 5:
            alerts.append({
                "alert_type": "SSH Brute Force",
                "severity": "High",
                "source_ip": source_ip,
                "destination_ip": "192.168.56.10",
                "description": (
                    f"Multiple failed SSH login attempts detected "
                    f"from {source_ip}: {count} failures"
                ),
                "mitre_technique": "T1110.001"
            })

    return alerts


def run_detection():

    if not INPUT_FILE.exists():
        print(f"[-] Input file not found: {INPUT_FILE}")
        return

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    events = []

    with INPUT_FILE.open("r") as infile:

        for line in infile:

            line = line.strip()

            if not line:
                continue

            try:
                events.append(json.loads(line))

            except json.JSONDecodeError:
                print("[-] Skipping invalid JSON line")

    alerts = []

    for event in events:

        port_scan_alert = detect_port_scan(event)

        if port_scan_alert:
            alerts.append(port_scan_alert)

        dns_alert = detect_dns_tunneling(event)

        if dns_alert:
            alerts.append(dns_alert)

    brute_force_alerts = detect_ssh_brute_force(events)

    alerts.extend(brute_force_alerts)

    with OUTPUT_FILE.open("w") as outfile:

        for alert in alerts:
            outfile.write(json.dumps(alert) + "\n")

    print(f"[+] Detection completed")
    print(f"[+] Total alerts: {len(alerts)}")
    print(f"[+] Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    run_detection()
