import os
import ipaddress
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"


def is_public_ip(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_global
    except ValueError:
        return False


def lookup_ip(ip_address):

    if not is_public_ip(ip_address):
        return {
            "ip": ip_address,
            "provider": "VirusTotal",
            "status": "skipped",
            "reason": "Private or non-routable IP"
        }

    if not API_KEY:
        return {
            "ip": ip_address,
            "provider": "VirusTotal",
            "status": "error",
            "reason": "VIRUSTOTAL_API_KEY not configured"
        }

    headers = {
        "x-apikey": API_KEY
    }

    url = f"{BASE_URL}/{ip_address}"

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()

            attributes = data.get("data", {}).get("attributes", {})

            return {
                "ip": ip_address,
                "provider": "VirusTotal",
                "status": "success",
                "reputation": attributes.get("reputation"),
                "malicious": attributes.get("last_analysis_stats", {}).get("malicious"),
                "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious")
            }

        return {
            "ip": ip_address,
            "provider": "VirusTotal",
            "status": "error",
            "http_status": response.status_code
        }

    except requests.RequestException as error:
        return {
            "ip": ip_address,
            "provider": "VirusTotal",
            "status": "error",
            "reason": str(error)
        }


if __name__ == "__main__":
    test_ip = "192.168.56.25"
    print(lookup_ip(test_ip))
