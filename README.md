# 🛡️ Advanced Threat Intelligence Platform (TIP) v2.0
### Finance & Banking Cybersecurity — Dynamic Policy Enforcer

An enterprise-grade, autonomous Threat Intelligence Platform built on Ubuntu Linux.  
The system continuously aggregates OSINT from multiple threat feeds, normalises and risk-scores data in MongoDB, and automatically enforces kernel-level firewall policies via `iptables` — with zero manual intervention.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      OSINT FEEDS                            │
│  FeodoTracker  │  Abuse.ch SSLBL  │  AlienVault OTX         │
└───────────────────────┬─────────────────────────────────────┘
                        │ raw indicators
                        ▼
┌─────────────────────────────────────────────────────────────┐
│              VALIDATION & NORMALISATION                     │
│  IP/Domain validation │ Deduplication │ Risk Scoring        │
└───────────────────────┬─────────────────────────────────────┘
                        │ clean documents
                        ▼
┌───────────────────────────────────┐
│           MongoDB                 │
│  indicators collection            │
│  • risk_score (0–100)             │
│  • is_blocked flag                │
│  • multi-source tracking          │
└───────────┬──────────┬────────────┘
            │          │
            ▼          ▼
┌──────────────┐  ┌──────────────────────────────────────┐
│ Elasticsearch│  │     DYNAMIC POLICY ENFORCER          │
│  (Kibana)    │  │  Reads high-risk unblocked IPs       │
│  optional    │  │  → iptables -A INPUT -s <IP> -j DROP │
└──────────────┘  │  → Updates DB is_blocked = True      │
                  │  → Discord / Slack alert             │
                  └──────────────────────────────────────┘
                                │
                                ▼
                  ┌──────────────────────────────────────┐
                  │     FLASK DASHBOARD (port 5000)      │
                  │  Stat cards │ Charts │ Live table    │
                  │  Emergency rollback UI               │
                  └──────────────────────────────────────┘
```

---

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Feed collection | Python (Requests) | Scrape OSINT APIs & CSV feeds |
| Data storage | MongoDB + PyMongo | NoSQL store with deduplication |
| Risk scoring | Custom algorithm | Multi-source weighted scoring |
| Firewall enforcement | Linux iptables + subprocess | Kernel-level IP blocking |
| SIEM sync | Elasticsearch 8 + Bulk API | Searchable threat landscape |
| Dashboard | Flask + Chart.js + DataTables | Real-time SOC observability |
| Alerting | Discord & Slack webhooks | Push notification on block events |
| Testing | pytest + unittest | Unit + integration + smoke tests |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/threat-intelligence-platform.git
cd threat-intelligence-platform

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment variables
cp .env.example .env
nano .env          # Fill in your API keys and webhook URLs

# 5. Ensure MongoDB is running
sudo systemctl start mongod

# 6. (Optional) Ensure Elasticsearch is running for ELK sync
sudo systemctl start elasticsearch
```

---

## Running the Platform

### Start the Master Daemon (requires root for iptables)
```bash
sudo ./venv/bin/python3 main.py
```
The daemon runs a full pipeline cycle every **5 minutes**:
1. Collect from all OSINT feeds
2. Validate & deduplicate indicators
3. Store/update in MongoDB with risk scores
4. Auto-block IPs with risk score ≥ BLOCK_THRESHOLD (default: 70)
5. Sync to Elasticsearch (if available)

### Launch the SOC Dashboard
```bash
python3 dashboard/app.py
# Opens automatically at http://localhost:5000
```

### Emergency IP Rollback (SOC Analyst)
```bash
# Unblock a single IP
sudo python3 -m enforcer.rollback 185.220.101.45

# Unblock ALL TIP-managed rules (full rollback)
sudo python3 -m enforcer.rollback --all
```

### API Rollback (from dashboard UI)
The dashboard includes a built-in rollback form. Enter the IP and click **INITIATE ROLLBACK**.  
This calls `POST /api/rollback` with `{"ip": "x.x.x.x"}`.

---

## REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Main SOC dashboard |
| GET | `/api/threats` | JSON list of all indicators |
| GET | `/api/stats` | Aggregated platform statistics |
| GET | `/api/blocked` | All currently blocked IPs |
| POST | `/api/rollback` | Unblock an IP (body: `{"ip":"..."}`) |

---

## Risk Score Algorithm

| Sources reporting | Base Score |
|-------------------|-----------|
| 1 source | 40 |
| 2 sources | 65 |
| 3+ sources | 85 |

**+10 bonus** if threat type matches: `ransomware`, `apt`, `botnet`, `qakbot`,  
`banking-trojan`, `malicious_ssl`, `emotet`, `trickbot`, `cobalt-strike`

**Maximum score: 100**

Auto-block triggers at score ≥ `BLOCK_THRESHOLD` (default 70, configurable via `.env`).

---

## Running Tests

```bash
# All tests (unit + integration + smoke)
python3 -m pytest tests/ -v

# Quick run without pytest
python3 tests/test_feeds.py
```

Tests cover:
- IP / domain validator (unit)
- Risk scoring algorithm (unit)
- Feodo Tracker feed schema validation (live)
- SSL Blacklist feed parsing (live)
- End-to-end pipeline smoke test (requires MongoDB)

---

## OSINT Feed Sources

| Feed | Type | API Key Required |
|------|------|-----------------|
| [Feodo Tracker](https://feodotracker.abuse.ch) | Botnet C2 IPs (JSON) | No |
| [Abuse.ch SSLBL](https://sslbl.abuse.ch) | Malicious SSL IPs (CSV) | No |
| [AlienVault OTX](https://otx.alienvault.com) | IPs + Domains (JSON API) | Yes (free) |

---

## Compliance & Logging

All actions are logged to the `logs/` directory:

| Log File | Contents |
|----------|----------|
| `system.log` | Master daemon pipeline events |
| `feeds.log` | Per-feed collection results |
| `firewall.log` | iptables block / rollback audit trail |
| `alerts.log` | Discord / Slack webhook dispatch records |
| `dashboard.log` | Dashboard and API access logs |

These logs serve as **immutable audit records** for PCI-DSS compliance reporting.

---

## User Personas

| Persona | Primary Use |
|---------|-------------|
| **SOC Analyst** | Monitor dashboard, review threat table, initiate rollbacks |
| **Security Engineer** | Review firewall logs, tune BLOCK_THRESHOLD, add new feeds |
| **Compliance Officer** | Export logs for PCI-DSS audit evidence |

---

*Built for autonomous SOC operations in the Finance & Banking sector.*
