import json
from pathlib import Path

from .virustotal import lookup_ip as vt_lookup
from .abuseipdb import lookup_ip as abuse_lookup


INPUT_FILE = Path("alerts/enriched/enriched_alerts.jsonl")
OUTPUT_FILE = Path("alerts/enriched/threat_intel_alerts.jsonl")


def enrich_alert(alert):
    source_ip = alert.get("source_ip")

    if not source_ip:
        return {
            **alert,
            "threat_intelligence": {
                "status": "skipped",
                "reason": "No source IP available"
            }
        }

    virus_total_result = vt_lookup(source_ip)
    abuseipdb_result = abuse_lookup(source_ip)

    return {
        **alert,
        "threat_intelligence": {
            "virustotal": virus_total_result,
            "abuseipdb": abuseipdb_result
        }
    }


def run_threat_intelligence():

    if not INPUT_FILE.exists():
        print(f"[-] Input file not found: {INPUT_FILE}")
        return

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    processed = 0

    with INPUT_FILE.open("r") as infile, OUTPUT_FILE.open("w") as outfile:

        for line in infile:

            line = line.strip()

            if not line:
                continue

            try:
                alert = json.loads(line)

                enriched_alert = enrich_alert(alert)

                outfile.write(
                    json.dumps(enriched_alert) + "\n"
                )

                processed += 1

            except json.JSONDecodeError:
                print("[-] Skipping invalid JSON alert")

    print("[+] Threat Intelligence enrichment completed")
    print(f"[+] Alerts processed: {processed}")
    print(f"[+] Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    run_threat_intelligence()
