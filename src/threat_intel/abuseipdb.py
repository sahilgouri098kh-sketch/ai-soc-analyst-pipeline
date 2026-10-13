import os
import ipaddress
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

BASE_URL = "https://api.abuseipdb.com/api/v2/check"


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
            "provider": "AbuseIPDB",
            "status": "skipped",
            "reason": "Private or non-routable IP"
        }

    if not API_KEY:
        return {
            "ip": ip_address,
            "provider": "AbuseIPDB",
            "status": "error",
            "reason": "ABUSEIPDB_API_KEY not configured"
        }

    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }

    params = {
        "ipAddress": ip_address
    }

    try:
        response = requests.get(
            BASE_URL,
            headers=headers,
            params=params,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            result = data.get("data", {})

            return {
                "ip": ip_address,
                "provider": "AbuseIPDB",
                "status": "success",
                "abuse_confidence_score": result.get(
                    "abuseConfidenceScore"
                ),
                "country_code": result.get("countryCode"),
                "isp": result.get("isp"),
                "domain": result.get("domain"),
                "total_reports": result.get("totalReports"),
                "last_reported_at": result.get("lastReportedAt")
            }

        return {
            "ip": ip_address,
            "provider": "AbuseIPDB",
            "status": "error",
            "http_status": response.status_code
        }

    except requests.RequestException as error:
        return {
            "ip": ip_address,
            "provider": "AbuseIPDB",
            "status": "error",
            "reason": str(error)
        }


if __name__ == "__main__":
    test_ip = "192.168.56.25"
    print(lookup_ip(test_ip))
