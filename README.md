# MiniSOAR

A lightweight terminal-based Security Orchestration tool that automates phishing investigations. Point it at a suspicious IP and a set of URLs, and it runs a structured playbook against **AbuseIPDB** and **VirusTotal**, scores the combined risk, and spits out a case report with a clear recommended action.

Built for home lab defenders, SOC students, and analysts who want a scripted first-pass on phishing alerts without clicking through three different dashboards.

---

## How It Works

```
You pass in an IP + URLs
        ↓
MiniSOAR checks the IP against AbuseIPDB
MiniSOAR checks each URL against VirusTotal
        ↓
Risk scores are accumulated across all checks
        ↓
Final verdict: AUTO-QUARANTINE / FLAGGED FOR REVIEW / MONITORING
```

Each run produces a **Case ID** (timestamp-based), a **risk score out of 100**, and a full findings log.

---

## Requirements

- Python 3.7+
- A free [VirusTotal API key](https://www.virustotal.com/gui/join-us)
- A free [AbuseIPDB API key](https://www.abuseipdb.com/register)

Install dependencies:

```bash
pip install requests python-dotenv
```

---

## Setup

Create a `.env` file in the same directory as the script:

```
VT_API_KEY=your_virustotal_key_here
ABUSEIPDB_KEY=your_abuseipdb_key_here
```

> Add `.env` to your `.gitignore`. Don't commit API keys.

---

## Usage

### Check an IP only
```bash
python minisoar.py --ip 185.220.101.45
```

### Check URLs only
```bash
python minisoar.py --urls http://paypal-secure-login.net/verify
```

### Check multiple URLs
```bash
python minisoar.py --urls http://paypal-secure-login.net/verify http://update-account.xyz/paypal
```

### Full phishing investigation (IP + URLs together)
```bash
python minisoar.py --ip 185.220.101.45 --urls http://paypal-secure-login.net/verify http://update-account.xyz/paypal
```

### Show help
```bash
python minisoar.py
# or
python minisoar.py --help
```

---

## Example Output

```
============================================================
  SOAR PLAYBOOK: Phishing Investigation
  Case ID: 20250514183042
============================================================

[PLAYBOOK STEP] Checking IP reputation: 185.220.101.45
  🚨 [CRITICAL] IP 185.220.101.45 — abuse score 100% (3,847 reports) [DE]

[PLAYBOOK STEP] Checking URL: http://paypal-secure-login.net/verify
  🚨 [CRITICAL] URL flagged by 14/89 engines — MALICIOUS

[PLAYBOOK STEP] Checking URL: http://update-account.xyz/paypal
  ⚠️ [WARN] URL flagged by 3/89 engines — Suspicious

[PLAYBOOK STEP] Calculating risk and recommendation...

============================================================
  SOAR CASE REPORT
============================================================
  Case ID:     20250514183042
  Risk Score:  100/100
  Action:      AUTO-QUARANTINE TRIGGERED

  Recommendation:
  HIGH RISK: Quarantine email from all inboxes. Block sender
  domain. Notify affected users. Escalate to Tier 2.

  Findings:
  [CRITICAL] IP 185.220.101.45 — abuse score 100% (3,847 reports) [DE]
  [CRITICAL] URL flagged by 14/89 engines — MALICIOUS
  [WARN]     URL flagged by 3/89 engines — Suspicious
============================================================
```

---

## Risk Scoring

Scores are additive across all checks in a single run.

| Condition | Points Added |
|---|---|
| IP abuse score ≥ 75% | +40 |
| IP abuse score 25–74% | +20 |
| IP abuse score < 25% | +0 |
| URL flagged by 5+ engines | +40 |
| URL flagged by 1–4 engines | +20 |
| URL clean | +0 |

| Final Score | Verdict | Action |
|---|---|---|
| ≥ 60 | High Risk | AUTO-QUARANTINE TRIGGERED |
| 30–59 | Medium Risk | FLAGGED FOR REVIEW |
| < 30 | Low Risk | MONITORING |

> The thresholds are intentionally conservative. Adjust them in the source if your environment has different tolerances.

---

## File Structure

```
.
├── minisoar.py     # The script
├── .env            # API keys — DO NOT commit
└── .gitignore      # Should include .env
```

**Minimum `.gitignore`:**
```
.env
__pycache__/
```

---

## API Limits (Free Tiers)

| Service | Limit |
|---|---|
| VirusTotal | 4 requests/min, 500/day |
| AbuseIPDB | 1,000 requests/day |

For bulk phishing triage across many alerts, consider adding a delay between runs or upgrading to a paid tier.

---

## License

MIT — free to use, adapt, and build on.
