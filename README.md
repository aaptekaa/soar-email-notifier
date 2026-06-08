# SOAR Email Notifier

Sends beautiful HTML email notifications when new incidents appear in **IBM QRadar SOAR**. Uses Exchange SMTP with STARTTLS. Runs as a systemd service.

## What it does

- Checks SOAR for new incidents every 30 seconds (comparing against the last known ID)
- Sends an HTML email with full incident details via Exchange SMTP
- Embeds the QRadar HTML description directly into the email (formatted offense details table)
- Displays Active Directory enrichment data in a dedicated section
- Persists the last processed incident ID so the service resumes correctly after restart

## Email Layout

Each notification contains:
- **Dark gradient header** with a color-coded severity badge
- **Three-column row**: Incident ID, severity level, creation date
- **QRadar section**: HTML table with offense ID, Source IP, categories, event count
- **Active Directory section**: user, department, account status, group membership
- **"Open in SOAR" button** with a direct link to the incident

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
- Exchange Server with SMTP enabled on port 587 (STARTTLS)
- A sender mailbox in Exchange
- RHEL/CentOS/Debian with systemd

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

CHECK_INTERVAL = 30   # Check interval in seconds
STATE_FILE = '/var/lib/soar-notifier/last_incident_id.txt'
```

### 4. Set baseline incident ID (recommended)

To avoid receiving emails for all historical incidents on first run:

```bash
# Find current max incident ID and write it
echo 2186 > /var/lib/soar-notifier/last_incident_id.txt
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
2026-06-08 09:43:53 [INFO] SOAR Email Notifier started
2026-06-08 09:43:53 [INFO] Starting from incident ID > 2184
2026-06-08 09:50:27 [INFO] Found 2 new incident(s)
2026-06-08 09:50:27 [INFO] Email sent for incident #2185: QRadar ID 133, Excessive Login Failures...
2026-06-08 09:50:28 [INFO] Email sent for incident #2186: QRadar ID 132, Excessive Login Failures...
```

## State Files

| File | Purpose |
|------|---------|
| `/var/lib/soar-notifier/last_incident_id.txt` | Last processed incident ID |
| `/var/log/soar-notifier.log` | Service log |

## Exchange Prerequisites

On the Exchange server:
1. Create a mailbox for the sender (`soar@domain.com`)
2. Enable Authenticated SMTP submission on port 587
3. Open port 587 in Windows Firewall for the SOAR server IP:
   ```
   netsh advfirewall firewall add rule name="SMTP-587 SOAR" dir=in action=allow protocol=TCP localport=587 remoteip=192.168.2.0/24
   ```

## Stack

- **IBM QRadar SOAR** 51.x
- **Microsoft Exchange** 2016+
- **Python** 3.6+
- **RHEL** 8.x / systemd