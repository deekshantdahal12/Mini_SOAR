import os
import sys
import base64
import argparse
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")

VT_HEADERS = {"x-apikey": VT_API_KEY}
ABUSE_HEADERS = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}


class MiniSOAR:
    def __init__(self):
        self.case = {
            "id": datetime.now().strftime("%Y%m%d%H%M%S"),
            "created": datetime.now().isoformat(),
            "type": "Phishing Investigation",
            "status": "In Progress",
            "risk_score": 0,
            "findings": [],
            "recommendation": ""
        }

    def log(self, msg, severity="INFO"):
        icons = {"INFO": "ℹ️", "WARN": "⚠️", "CRITICAL": "🚨", "OK": "✅"}
        print(f"  {icons.get(severity, '')} [{severity}] {msg}")
        self.case["findings"].append({
            "time": datetime.now().isoformat(),
            "severity": severity,
            "message": msg
        })

    def check_ip(self, ip):
        print(f"\n[PLAYBOOK STEP] Checking IP reputation: {ip}")
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=ABUSE_HEADERS,
                params={"ipAddress": ip, "maxAgeInDays": "90"}
            )
            d = r.json()["data"]
            score = d["abuseConfidenceScore"]
            reports = d["totalReports"]
            country = d["countryCode"]

            if score >= 75:
                self.case["risk_score"] += 40
                self.log(f"IP {ip} — abuse score {score}% ({reports} reports) [{country}]", "CRITICAL")
            elif score >= 25:
                self.case["risk_score"] += 20
                self.log(f"IP {ip} — abuse score {score}% ({reports} reports) [{country}]", "WARN")
            else:
                self.log(f"IP {ip} appears clean (score: {score}%) [{country}]", "OK")

        except Exception as e:
            self.log(f"IP check failed for {ip}: {e}", "WARN")

    def check_url(self, url):
        print(f"\n[PLAYBOOK STEP] Checking URL: {url}")
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            r = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=VT_HEADERS
            )
            if r.status_code != 200:
                self.log(f"VT returned {r.status_code} for {url}", "WARN")
                return

            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())

            if malicious >= 5:
                self.case["risk_score"] += 40
                self.log(f"URL flagged by {malicious}/{total} engines — MALICIOUS", "CRITICAL")
            elif malicious >= 1:
                self.case["risk_score"] += 20
                self.log(f"URL flagged by {malicious}/{total} engines — Suspicious", "WARN")
            else:
                self.log(f"URL clean ({malicious}/{total})", "OK")

        except Exception as e:
            self.log(f"URL check failed: {e}", "WARN")

    def run_phishing_playbook(self, email_data):
        print("\n" + "=" * 60)
        print("  SOAR PLAYBOOK: Phishing Investigation")
        print(f"  Case ID: {self.case['id']}")
        print("=" * 60)

        if email_data.get("sender_ip"):
            self.check_ip(email_data["sender_ip"])

        for url in email_data.get("urls", []):
            self.check_url(url)

        print("\n[PLAYBOOK STEP] Calculating risk and recommendation...")
        score = self.case["risk_score"]

        if score >= 60:
            self.case["recommendation"] = (
                "HIGH RISK: Quarantine email from all inboxes. "
                "Block sender domain. Notify affected users. Escalate to Tier 2."
            )
            action = "AUTO-QUARANTINE TRIGGERED"
        elif score >= 30:
            self.case["recommendation"] = (
                "MEDIUM RISK: Flag email as suspicious. "
                "Notify recipient. Request analyst review."
            )
            action = "FLAGGED FOR REVIEW"
        else:
            self.case["recommendation"] = (
                "LOW RISK: Monitor for similar patterns. No immediate action required."
            )
            action = "MONITORING"

        print("\n" + "=" * 60)
        print("  SOAR CASE REPORT")
        print("=" * 60)
        print(f"  Case ID:     {self.case['id']}")
        print(f"  Risk Score:  {score}/100")
        print(f"  Action:      {action}")
        print(f"\n  Recommendation:\n  {self.case['recommendation']}")
        print("\n  Findings:")
        for f in self.case["findings"]:
            print(f"  [{f['severity']}] {f['message']}")
        print("=" * 60)

        return self.case


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MiniSOAR — Automated phishing investigation playbook",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--ip", metavar="ADDRESS",
                        help="Sender IP address to check against AbuseIPDB")
    parser.add_argument("--urls", metavar="URL", nargs="+",
                        help="One or more URLs to check against VirusTotal")

    args = parser.parse_args()

    # Nothing passed — just show help
    if not args.ip and not args.urls:
        parser.print_help()
        sys.exit(0)

    soar = MiniSOAR()
    soar.run_phishing_playbook({
        "sender_ip": args.ip,
        "urls": args.urls or []
    })