import json
from pathlib import Path


INPUT_FILE = Path("logs/generated/security_logs.jsonl")
OUTPUT_FILE = Path("data/processed/normalized_logs.jsonl")


def parse_logs():
    if not INPUT_FILE.exists():
        print(f"[-] Log file not found: {INPUT_FILE}")
        return

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    parsed_count = 0
    error_count = 0

    with INPUT_FILE.open("r") as infile, OUTPUT_FILE.open("w") as outfile:

        for line_number, line in enumerate(infile, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)

                normalized_event = {
                    "timestamp": event.get("timestamp"),
                    "event_type": event.get("event_type"),
                    "source_ip": event.get("source_ip"),
                    "destination_ip": event.get("destination_ip"),
                    "username": event.get("username"),
                    "status": event.get("status"),
                    "raw_event": event
                }

                outfile.write(
                    json.dumps(normalized_event) + "\n"
                )

                parsed_count += 1

            except json.JSONDecodeError:
                print(f"[-] Invalid JSON at line {line_number}")
                error_count += 1

    print(f"[+] Parsed logs: {parsed_count}")
    print(f"[+] Errors: {error_count}")
    print(f"[+] Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    parse_logs()
