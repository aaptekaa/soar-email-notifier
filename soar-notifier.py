#!/usr/bin/env python3
import time
import logging
import smtplib
import ssl
import os
import re
import requests
import urllib3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SOAR_URL = "https://192.168.2.80"
SOAR_EMAIL = "administrator@test.com"
SOAR_PASSWORD = "AdminPass"
SOAR_ORG_ID = 201

SMTP_HOST = "192.168.5.2"
SMTP_PORT = 587
SMTP_USER = "soar@test.comb"
SMTP_PASS = "AdminPass"
SMTP_FROM = "soar@test.com"
SMTP_TO = "administrator@test.com"

CHECK_INTERVAL = 30
STATE_FILE = "/var/lib/soar-notifier/last_incident_id.txt"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("/var/log/soar-notifier.log")]
)
log = logging.getLogger(__name__)

SEVERITY_MAP = {
    1: ("Low", "#28a745"),
    2: ("Low", "#28a745"),
    3: ("Medium", "#fd7e14"),
    4: ("Medium", "#fd7e14"),
    5: ("High", "#dc3545"),
    6: ("High", "#dc3545"),
    7: ("Critical", "#6f42c1"),
    8: ("Critical", "#6f42c1"),
    9: ("Critical", "#6f42c1"),
    10: ("Critical", "#6f42c1"),
}


def strip_html(html):
    return re.sub(r"<[^>]+>", " ", html or "").strip()


def get_soar_session():
    session = requests.Session()
    session.verify = False
    resp = session.post(
        f"{SOAR_URL}/rest/session",
        json={"email": SOAR_EMAIL, "password": SOAR_PASSWORD},
        timeout=30
    )
    resp.raise_for_status()
    data = resp.json()
    csrf = data.get("csrf_token", "")
    session.headers.update({
        "X-sess-id": csrf,
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/json"
    })
    log.info("Logged in to SOAR successfully")
    return session


def get_incidents(session, since_id=0):
    resp = session.get(
        f"{SOAR_URL}/rest/orgs/{SOAR_ORG_ID}/incidents",
        params={"want_closed": "false"},
        timeout=30
    )
    if resp.status_code == 401:
        return None, True
    resp.raise_for_status()
    data = resp.json()
    incidents = data if isinstance(data, list) else data.get("entities", [])
    new = [i for i in incidents if i.get("id", 0) > since_id]
    return sorted(new, key=lambda x: x.get("id", 0)), False


def build_html_email(inc_id, inc_name, severity_code, created, description_html, url):
    sev_label, sev_color = SEVERITY_MAP.get(int(severity_code) if str(severity_code).isdigit() else 0, ("Unknown", "#6c757d"))

    desc_block = ""
    if description_html:
        desc_block = f"""
        <tr>
          <td style="padding:16px 24px 0;">
            <p style="margin:0 0 6px;font-size:12px;font-weight:600;color:#555;text-transform:uppercase;letter-spacing:.5px;">Description</p>
            <div style="background:#f8f9fa;border:1px solid #e9ecef;border-radius:6px;padding:12px 16px;font-size:13px;color:#333;">
              {description_html}
            </div>
          </td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f2f5;padding:32px 0;">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.12);">

      <!-- Header -->
      <tr>
        <td style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);padding:24px 24px 20px;">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td>
                <p style="margin:0;font-size:11px;color:#8899aa;text-transform:uppercase;letter-spacing:1px;">IBM QRadar SOAR</p>
                <p style="margin:4px 0 0;font-size:20px;font-weight:700;color:#fff;">New Incident</p>
              </td>
              <td align="right">
                <span style="background:{sev_color};color:#fff;font-size:12px;font-weight:700;padding:5px 14px;border-radius:20px;text-transform:uppercase;letter-spacing:.5px;">{sev_label}</span>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- Incident title -->
      <tr>
        <td style="padding:20px 24px 12px;border-bottom:1px solid #e9ecef;">
          <p style="margin:0 0 4px;font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.5px;">Incident Name</p>
          <p style="margin:0;font-size:15px;font-weight:600;color:#1a1a2e;">{inc_name}</p>
        </td>
      </tr>

      <!-- Key fields -->
      <tr>
        <td style="padding:16px 24px 0;">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td width="33%" style="padding:0 8px 12px 0;vertical-align:top;">
                <p style="margin:0 0 3px;font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.5px;">Incident ID</p>
                <p style="margin:0;font-size:22px;font-weight:700;color:#0f3460;">#{inc_id}</p>
              </td>
              <td width="33%" style="padding:0 8px 12px;vertical-align:top;">
                <p style="margin:0 0 3px;font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.5px;">Severity</p>
                <p style="margin:0;font-size:15px;font-weight:600;color:{sev_color};">{sev_label} ({severity_code})</p>
              </td>
              <td width="33%" style="padding:0 0 12px 8px;vertical-align:top;">
                <p style="margin:0 0 3px;font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.5px;">Created</p>
                <p style="margin:0;font-size:13px;color:#333;">{created}</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      {desc_block}

      <!-- Action button -->
      <tr>
        <td style="padding:20px 24px 24px;">
          <a href="{url}" style="display:inline-block;background:#0f3460;color:#fff;text-decoration:none;font-size:13px;font-weight:600;padding:10px 24px;border-radius:6px;">
            Open in SOAR &rarr;
          </a>
        </td>
      </tr>

      <!-- Footer -->
      <tr>
        <td style="background:#f8f9fa;border-top:1px solid #e9ecef;padding:14px 24px;">
          <p style="margin:0;font-size:11px;color:#999;">Automated notification from IBM QRadar SOAR &bull; {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
        </td>
      </tr>

    </table>
  </td></tr>
</table>
</body>
</html>"""


def send_email(incident):
    inc_id = incident.get("id", "N/A")
    inc_name = incident.get("name", "Unknown")
    severity = incident.get("severity_code", "N/A")
    created_ts = incident.get("create_date", 0)
    created = datetime.fromtimestamp(created_ts / 1000).strftime("%Y-%m-%d %H:%M:%S") if created_ts else "N/A"
    description = incident.get("description", {})
    if isinstance(description, dict):
        description = description.get("content", "")

    url = f"{SOAR_URL}/#incidents/{inc_id}"
    subject = f"[SOAR] New Incident #{inc_id}: {inc_name[:60]}"

    html_body = build_html_email(inc_id, inc_name, severity, created, description, url)

    plain_desc = strip_html(description) if description else "N/A"
    plain_body = (
        f"IBM QRadar SOAR - New Incident\n"
        f"{'='*50}\n\n"
        f"ID:          #{inc_id}\n"
        f"Name:        {inc_name}\n"
        f"Severity:    {severity}\n"
        f"Created:     {created}\n"
        f"Description: {plain_desc}\n\n"
        f"URL: {url}\n"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = SMTP_TO
    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        server.ehlo()
        server.starttls(context=ctx)
        server.ehlo()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_FROM, [SMTP_TO], msg.as_string())

    log.info(f"Email sent for incident #{inc_id}: {inc_name}")


def load_last_id():
    try:
        with open(STATE_FILE, "r") as f:
            return int(f.read().strip())
    except Exception:
        return 0


def save_last_id(inc_id):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        f.write(str(inc_id))


def main():
    log.info("SOAR Email Notifier started")
    log.info(f"Monitoring: {SOAR_URL} | Sending to: {SMTP_TO}")

    last_id = load_last_id()
    log.info(f"Starting from incident ID > {last_id}")

    session = None

    while True:
        try:
            if session is None:
                session = get_soar_session()

            incidents, need_reauth = get_incidents(session, last_id)

            if need_reauth:
                log.warning("Session expired, re-authenticating...")
                session = None
                continue

            if incidents:
                log.info(f"Found {len(incidents)} new incident(s)")
                for incident in incidents:
                    try:
                        send_email(incident)
                        if incident.get("id", 0) > last_id:
                            last_id = incident["id"]
                            save_last_id(last_id)
                    except Exception as e:
                        log.error(f"Failed to send email for incident {incident.get('id')}: {e}")
            else:
                log.debug("No new incidents")

        except requests.exceptions.ConnectionError as e:
            log.error(f"Connection error: {e}")
            session = None
        except Exception as e:
            log.error(f"Error: {e}", exc_info=True)
            session = None

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
