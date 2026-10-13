import json
import unittest

from src.upload_analyzer import analyze_events, parse_uploaded_file


class UploadAnalyzerTests(unittest.TestCase):
    def test_jsonl_ssh_brute_force_detection(self):
        rows = [
            {
                "timestamp": f"2026-10-13T10:00:0{i}",
                "event_type": "ssh_failed_login",
                "source_ip": "198.51.100.8",
                "destination_ip": "10.0.0.2",
                "username": "admin",
                "status": "failed",
            }
            for i in range(5)
        ]
        content = "".join(json.dumps(row) + "\n" for row in rows).encode()
        events, errors = parse_uploaded_file("auth.jsonl", content)
        alerts = analyze_events(events)
        self.assertEqual(errors, 0)
        self.assertEqual(len(events), 5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "SSH Brute Force")

    def test_port_scan_detection(self):
        content = json.dumps({
            "event_type": "port_scan",
            "source_ip": "198.51.100.8",
            "destination_ip": "10.0.0.2",
            "ports_scanned": 150,
        }).encode()
        events, errors = parse_uploaded_file("scan.json", content)
        alerts = analyze_events(events)
        self.assertEqual(errors, 0)
        self.assertEqual(alerts[0]["alert_type"], "Port Scan")

    def test_common_linux_auth_lines(self):
        content = "\n".join(
            f"Oct 13 10:00:0{i} host sshd[100]: Failed password for admin "
            "from 198.51.100.8 port 22 ssh2"
            for i in range(5)
        ).encode()
        events, errors = parse_uploaded_file("auth.log", content)
        self.assertEqual(errors, 0)
        self.assertEqual(len(events), 5)
        self.assertEqual(events[0]["username"], "admin")
        self.assertEqual(len(analyze_events(events)), 1)

    def test_reject_unsupported_extension(self):
        with self.assertRaises(ValueError):
            parse_uploaded_file("events.evtx", b"not supported")


if __name__ == "__main__":
    unittest.main()
