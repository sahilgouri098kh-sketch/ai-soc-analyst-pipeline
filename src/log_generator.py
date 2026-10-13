
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

OUTPUT_FILE = Path("logs/generated/security_logs.jsonl")


def generate_ssh_failed_login(timestamp):
    return {
        "timestamp": timestamp.isoformat(),
        "event_type": "ssh_failed_login",
        "source_ip": random.choice([
            "192.168.56.20",
            "192.168.56.21",
            "192.168.56.22"
        ]),
        "destination_ip": "192.168.56.10",
        "username": random.choice(["admin", "root", "user"]),
        "status": "failed"
    }


def generate_normal_login(timestamp):
    return {
        "timestamp": timestamp.isoformat(),
        "event_type": "ssh_login",
        "source_ip": "192.168.56.15",
        "destination_ip": "192.168.56.10",
        "username": "sahil",
        "status": "success"
    }


def generate_sudo_event(timestamp):
    return {
        "timestamp": timestamp.isoformat(),
        "event_type": "sudo_command",
        "source_ip": "192.168.56.15",
        "username": "sahil",
        "command": "sudo systemctl restart ssh",
        "status": "executed"
    }


def generate_port_scan(timestamp):
    return {
        "timestamp": timestamp.isoformat(),
        "event_type": "port_scan",
        "source_ip": "192.168.56.20",
        "destination_ip": "192.168.56.10",
        "ports_scanned": random.randint(50, 200),
        "protocol": "TCP"
    }


def generate_dns_tunneling(timestamp):
    query = (
        "aGVsbG8tdGhpcy1pcy1hLXRlc3QubWFsaWNpb3VzLmV4YW1wbGU="
    )
    return {
        "timestamp": timestamp.isoformat(),
        "event_type": "dns_query",
        "source_ip": "192.168.56.25",
        "destination_ip": "192.168.56.1",
        "query": query,
        "query_length": len(query),
        "record_type": "TXT"
    }


def generate_c2_beacon(timestamp):
    return {
        "timestamp": timestamp.isoformat(),
        "event_type": "c2_beacon",
        "source_ip": "192.168.56.25",
        "destination_ip": "192.168.56.30",
        "destination_port": 443,
        "protocol": "HTTPS",
        "interval_seconds": random.randint(55, 65)
    }


def generate_logs(number_of_logs=100):
    start_time = datetime.now()
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    generators = [
        generate_normal_login,
        generate_ssh_failed_login,
        generate_sudo_event,
        generate_port_scan,
        generate_dns_tunneling,
        generate_c2_beacon
    ]

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        # Controlled burst: six failed SSH logins from one source.
        for attempt in range(6):
            timestamp = start_time + timedelta(seconds=attempt * 2)
            event = {
                "timestamp": timestamp.isoformat(),
                "event_type": "ssh_failed_login",
                "source_ip": "192.168.56.99",
                "destination_ip": "192.168.56.10",
                "username": "admin",
                "status": "failed"
            }
            file.write(json.dumps(event) + "\n")

        # Generate the requested number of additional events.
        for i in range(number_of_logs):
            timestamp = start_time + timedelta(seconds=15 + i * 5)

            if random.random() < 0.55:
                event = generate_normal_login(timestamp)
            else:
                event = random.choice(generators[1:])(timestamp)

            file.write(json.dumps(event) + "\n")

    print(f"[+] Generated {number_of_logs} random logs")
    print("[+] Added 6 controlled SSH failed-login events")
    print(f"[+] Total events: {number_of_logs + 6}")
    print(f"[+] Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    generate_logs(100)
