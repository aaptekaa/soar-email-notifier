# SOAR Email Notifier

Sends HTML email notifications for **new** and **closed** incidents in **IBM QRadar SOAR**. Uses Exchange SMTP with STARTTLS. Runs as a systemd service, polling every 30 seconds.

## Features

- **New incident** email — sent immediately when a new incident appears in SOAR
- **Closed incident** email — sent when an incident is closed, with full closure details
- Tracks who opened and who closed each incident (from SOAR audit history)
- Shows resolution type, resolution notes, and time-to-close duration
- On startup, automatically seeds all currently open incidents into tracking (no duplicate emails)
- Persists state in JSON across restarts — safe to restart anytime
- Backward-compatible with old `last_incident_id.txt` state file (auto-migrates)

## Email: New Incident

Dark gradient header with severity badge and incident details:

- Incident ID, severity (color-coded), creation date
- Full QRadar offense description (HTML table: Source IP, categories, event count)
- **Open in SOAR** button

Subject: `[SOAR] New Incident #2191: QRadar ID 138, Excessive Login Failures...`

## Email: Incident Closed

Green gradient header with full closure summary:

| Field | Example |
|-------|---------|
| Incident ID | #2190 |
| Severity | High (5) |
| Duration | 1h 5m |
| Opened | 2026-06-08 11:09:23 (by Maxim Adminov) |
| Closed | 2026-06-08 12:17:55 (by Maxim Adminov) |
| Resolution | Resolved |
| Resolution Notes | Investigation complete, threat mitigated |

Subject: `[SOAR] Incident Closed #2190: QRadar ID 136, Excessive Login Failures...`

## Severity Color Scheme

| Level    | Color  | SOAR Severity |
|----------|--------|---------------|
| Low      | Green  | 1–2           |
| Medium   | Orange | 3–4           |
| High     | Red    | 5–6           |
| Critical | Purple | 7–10          |

## Installation

### Requirements

- Python 3.6+
- `requests` library (`pip install requests`)
- Exchange Server with SMTP on port 587 (STARTTLS)
- A sender mailbox in Exchange
- RHEL / CentOS / Debian with systemd

### 1. Install dependencies

```bash
pip3 install requests
```

### 2. Copy the script

```bash
cp soar-notifier.py /opt/soar-notifier.py
chmod +x /opt/soar-notifier.py
mkdir -p /var/lib/soar-notifier
```

### 3. Configure

Edit the variables at the top of `soar-notifier.py`:

```python
SOAR_URL      = 'https://192.168.2.80'   # IBM SOAR URL
SOAR_EMAIL    = 'admin@example.com'       # SOAR login
SOAR_PASSWORD = 'password'                # SOAR password
SOAR_ORG_ID   = 201                       # SOAR organization ID

SMTP_HOST = '192.168.5.2'       # Exchange server IP
SMTP_PORT = 587                  # SMTP port (587 = STARTTLS)
SMTP_USER = 'soar@example.com'  # Sender account
SMTP_PASS = 'password'           # Sender password
SMTP_FROM = 'soar@example.com'  # From address
SMTP_TO   = 'admin@example.com' # Recipient

CHECK_INTERVAL = 30   # Poll interval in seconds
```

### 4. Set baseline (optional, prevents flood on first run)

```bash
echo 2190 > /var/lib/soar-notifier/last_incident_id.txt
```

### 5. Install systemd service

```bash
cp soar-notifier.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable soar-notifier.service
systemctl start soar-notifier.service
```

### 6. Verify

```bash
systemctl status soar-notifier.service
tail -f /var/log/soar-notifier.log
```

## Log Example

```
2026-06-08 12:16:27 [INFO] SOAR Email Notifier started (new + closed incidents)
2026-06-08 12:16:27 [INFO] Starting from incident ID > 2190, tracking 0 open incident(s)
2026-06-08 12:16:27 [INFO] Seeded 2 currently open incident(s) for closure tracking
2026-06-08 12:17:00 [INFO] Found 1 new incident(s)
2026-06-08 12:17:00 [INFO] New incident email sent for #2191: QRadar ID 138...
2026-06-08 12:17:58 [INFO] Closure email sent for incident #2190: QRadar ID 136...
```

## State File

State is stored in `/var/lib/soar-notifier/state.json`:

```json
{
  "last_id": 2191,
  "open_incidents": {
    "2191": {
      "name": "QRadar ID 138, Excessive Login Failures...",
      "create_ts": 1780902649932
    }
  }
}
```

| File | Purpose |
|------|---------|
| `/var/lib/soar-notifier/state.json` | Last ID + open incidents tracking |
| `/var/log/soar-notifier.log` | Service log |

## Exchange Prerequisites

On the Exchange server:

1. Create a sender mailbox (`soar@domain.com`)
2. Enable Authenticated SMTP submission on port 587
3. Open port 587 in Windows Firewall for the SOAR server:

```
netsh advfirewall firewall add rule name="SMTP-587 SOAR" ^
  dir=in action=allow protocol=TCP localport=587 remoteip=192.168.2.0/24
```

## Stack

- **IBM QRadar SOAR** 51.x
- **Microsoft Exchange** 2016+
- **Python** 3.6+
- **RHEL** 8.x / systemd
