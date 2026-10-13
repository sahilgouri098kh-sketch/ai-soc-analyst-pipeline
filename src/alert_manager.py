import json
from pathlib import Path
from collections import defaultdict


INPUT_FILE = Path("alerts/raw/detection_alerts.jsonl")
OUTPUT_FILE = Path("alerts/enriched/enriched_alerts.jsonl")


def group_alerts():
    if not INPUT_FILE.exists():
        print(f"[-] Alert file not found: {INPUT_FILE}")
        return

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    grouped = defaultdict(list)

    with INPUT_FILE.open("r") as infile:

        for line in infile:
            line = line.strip()

            if not line:
                continue

            alert = json.loads(line)

            key = (
                alert.get("alert_type"),
                alert.get("source_ip"),
                alert.get("destination_ip")
            )

            grouped[key].append(alert)

    enriched_alerts = []

    for key, alerts in grouped.items():

        first_alert = alerts[0]

        enriched_alert = {
            "alert_id": f"ALERT-{len(enriched_alerts) + 1:04d}",
            "alert_type": first_alert.get("alert_type"),
            "severity": first_alert.get("severity"),
            "source_ip": first_alert.get("source_ip"),
            "destination_ip": first_alert.get("destination_ip"),
            "mitre_technique": first_alert.get("mitre_technique"),
            "first_seen": alerts[0].get("timestamp"),
            "last_seen": alerts[-1].get("timestamp"),
            "event_count": len(alerts),
            "description": first_alert.get("description")
        }

        enriched_alerts.append(enriched_alert)

    with OUTPUT_FILE.open("w") as outfile:

        for alert in enriched_alerts:
            outfile.write(json.dumps(alert) + "\n")

    print(f"[+] Raw alerts: {sum(len(v) for v in grouped.values())}")
    print(f"[+] Grouped alerts: {len(enriched_alerts)}")
    print(f"[+] Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    group_alerts()
