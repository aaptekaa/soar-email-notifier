#!/usr/bin/env python3
import time
import logging
import smtplib
import ssl
import os
import re
import json
import requests
import urllib3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SOAR_URL      = "https://192.168.2.80"
SOAR_EMAIL    = "administrator@test.com"
SOAR_PASSWORD = "AdminPass"
SOAR_ORG_ID   = 201

SMTP_HOST = "192.168.5.2"
SMTP_PORT = 587
SMTP_USER = "soar@test.com"
SMTP_PASS = "AdminPass"
SMTP_FROM = "soar@test.com"
SMTP_TO   = "administrator@test.com"

CHECK_INTERVAL = 30
STATE_FILE     = "/var/lib/soar-notifier/state.json"
OLD_STATE_FILE = "/var/lib/soar-notifier/last_incident_id.txt"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("/var/log/soar-notifier.log")]
)
log = logging.getLogger(__name__)

SEVERITY_MAP = {
    1: ("Low",      "#28a745"),
    2: ("Low",      "#28a745"),
    3: ("Medium",   "#fd7e14"),
    4: ("Medium",   "#fd7e14"),
    5: ("High",     "#dc3545"),
    6: ("High",     "#dc3545"),
    7: ("Critical", "#6f42c1"),
    8: ("Critical", "#6f42c1"),
    9: ("Critical", "#6f42c1"),
    10:("Critical", "#6f42c1"),
}

RESOLUTION_MAP = {
    1:  "Unresolved",
    2:  "Duplicate",
    3:  "Not an Issue",
    4:  "Resolved",
    5:  "False Positive",
    6:  "Merged",
    7:  "Threat Mitigated",
    8:  "User Notified",
    9:  "No Action Required",
    10: "Resolved",
}


# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------

def load_state():
    """Load state from JSON. Migrates from old txt file if needed."""
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        pass
    # Migrate from old format
    last_id = 0
    try:
        with open(OLD_STATE_FILE) as f:
            last_id = int(f.read().strip())
    except Exception:
        pass
    return {"last_id": last_id, "open_incidents": {}}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ---------------------------------------------------------------------------
# SOAR API
# ---------------------------------------------------------------------------

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
    session.headers.update({
        "X-sess-id":        data.get("csrf_token", ""),
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type":     "application/json"
    })
    log.info("Logged in to SOAR successfully")
    return session


def get_open_incidents(session):
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
    return incidents, False


def get_incident_detail(session, inc_id):
    try:
        resp = session.get(
            f"{SOAR_URL}/rest/orgs/{SOAR_ORG_ID}/incidents/{inc_id}",
            timeout=30
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        log.warning(f"Could not fetch detail for incident #{inc_id}: {e}")
        return {}


def get_incident_history(session, inc_id):
    try:
        resp = session.get(
            f"{SOAR_URL}/rest/orgs/{SOAR_ORG_ID}/incidents/{inc_id}/history",
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("incident_detail_history", [])
    except Exception as e:
        log.warning(f"Could not fetch history for incident #{inc_id}: {e}")
        return []


def get_closure_info(history):
    """
    Extract who closed the incident and when from history.
    Returns (closer_name, closed_ts, resolution_name, resolution_summary).
    """
    closer_name      = "Unknown"
    closed_ts        = None
    resolution_name  = "Unknown"
    resolution_summary = ""

    for entry in reversed(history):
        diffs = entry.get("diffs", [])
        for diff in diffs:
            if diff.get("name") == "Status" and diff.get("new_val") == "Closed":
                closer_name = entry.get("user", "Unknown")
                closed_ts   = entry.get("date")
            if diff.get("name") == "Resolution":
                resolution_name = diff.get("new_val", "Unknown")
            if diff.get("name") == "Resolution Summary":
                val = diff.get("new_val", {})
                if isinstance(val, dict):
                    resolution_summary = strip_html(val.get("content", ""))
                else:
                    resolution_summary = strip_html(str(val))

    return closer_name, closed_ts, resolution_name, resolution_summary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def strip_html(html):
    return re.sub(r"<[^>]+>", " ", html or "").strip()


def fmt_ts(ts_ms):
    if not ts_ms:
        return "N/A"
    return datetime.fromtimestamp(ts_ms / 1000).strftime("%Y-%m-%d %H:%M:%S")


def duration_str(open_ts_ms, close_ts_ms):
    if not open_ts_ms or not close_ts_ms:
        return "N/A"
    secs = int((close_ts_ms - open_ts_ms) / 1000)
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    h = secs // 3600
    m = (secs % 3600) // 60
    return f"{h}h {m}m"


# ---------------------------------------------------------------------------
# Email builders
# ---------------------------------------------------------------------------

def build_new_incident_email(incident):
    inc_id     = incident.get("id", "N/A")
    inc_name   = incident.get("name", "Unknown")
    severity   = incident.get("severity_code", "N/A")
    created_ts = incident.get("create_date", 0)
    created    = fmt_ts(created_ts)
    description = incident.get("description", {})
    if isinstance(description, dict):
        description = description.get("content", "")
    url = f"{SOAR_URL}/#incidents/{inc_id}"

    sev_int = int(severity) if str(severity).isdigit() else 0
    sev_label, sev_color = SEVERITY_MAP.get(sev_int, ("Unknown", "#6c757d"))

    desc_block = ""
    if description:
        desc_block = f"""
      <tr>
        <td style="padding:16px 24px 0;">
          <p style="margin:0 0 6px;font-size:12px;font-weight:600;color:#555;text-transform:uppercase;letter-spacing:.5px;">Description</p>
          <div style="background:#f8f9fa;border:1px solid #e9ecef;border-radius:6px;padding:12px 16px;font-size:13px;color:#333;">
            {description}
          </div>
        </td>
      </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f2f5;padding:32px 0;">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.12);">

      <tr>
        <td style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);padding:24px 24px 20px;">
          <table width="100%" cellpadding="0" cellspacing="0"><tr>
            <td>
              <p style="margin:0;font-size:11px;color:#8899aa;text-transform:uppercase;letter-spacing:1px;">IBM QRadar SOAR</p>
              <p style="margin:4px 0 0;font-size:20px;font-weight:700;color:#fff;">&#9888; New Incident</p>
            </td>
            <td align="right">
              <span style="background:{sev_color};color:#fff;font-size:12px;font-weight:700;padding:5px 14px;border-radius:20px;text-transform:uppercase;">{sev_label}</span>
            </td>
          </tr></table>
        </td>
      </tr>

      <tr>
        <td style="padding:20px 24px 12px;border-bottom:1px solid #e9ecef;">
          <p style="margin:0 0 4px;font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.5px;">Incident Name</p>
          <p style="margin:0;font-size:15px;font-weight:600;color:#1a1a2e;">{inc_name}</p>
        </td>
      </tr>

      <tr>
        <td style="padding:16px 24px 0;">
          <table width="100%" cellpadding="0" cellspacing="0"><tr>
            <td width="33%" style="padding:0 8px 12px 0;vertical-align:top;">
              <p style="margin:0 0 3px;font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.5px;">Incident ID</p>
              <p style="margin:0;font-size:22px;font-weight:700;color:#0f3460;">#{inc_id}</p>
            </td>
            <td width="33%" style="padding:0 8px 12px;vertical-align:top;">
              <p style="margin:0 0 3px;font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.5px;">Severity</p>
              <p style="margin:0;font-size:15px;font-weight:600;color:{sev_color};">{sev_label} ({severity})</p>
            </td>
            <td width="33%" style="padding:0 0 12px 8px;vertical-align:top;">
              <p style="margin:0 0 3px;font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.5px;">Created</p>
              <p style="margin:0;font-size:13px;color:#333;">{created}</p>
            </td>
          </tr></table>
        </td>
      </tr>

      {desc_block}

      <tr>
        <td style="padding:20px 24px 24px;">
          <a href="{url}" style="display:inline-block;background:#0f3460;color:#fff;text-decoration:none;font-size:13px;font-weight:600;padding:10px 24px;border-radius:6px;">
            Open in SOAR &rarr;
          </a>
        </td>
      </tr>

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

    plain = (
        f"IBM QRadar SOAR - New Incident\n"
        f"{'='*50}\n\n"
        f"ID:          #{inc_id}\n"
        f"Name:        {inc_name}\n"
        f"Severity:    {sev_label} ({severity})\n"
        f"Created:     {created}\n"
        f"Description: {strip_html(description) or 'N/A'}\n\n"
        f"URL: {url}\n"
    )

    return f"[SOAR] New Incident #{inc_id}: {inc_name[:60]}", html, plain


def build_closed_incident_email(detail, history):
    inc_id     = detail.get("id", "N/A")
    inc_name   = detail.get("name", "Unknown")
    severity   = detail.get("severity_code", "N/A")
    created_ts = detail.get("create_date", 0)
    end_ts     = detail.get("end_date", 0)
    url        = f"{SOAR_URL}/#incidents/{inc_id}"

    sev_int = int(severity) if str(severity).isdigit() else 0
    sev_label, sev_color = SEVERITY_MAP.get(sev_int, ("Unknown", "#6c757d"))

    closer_name, closed_ts, resolution_name, resolution_summary = get_closure_info(history)

    # Use end_date from detail if history didn't provide it
    if not closed_ts:
        closed_ts = end_ts

    created_str  = fmt_ts(created_ts)
    closed_str   = fmt_ts(closed_ts)
    duration     = duration_str(created_ts, closed_ts)
    creator      = detail.get("creator", {})
    creator_name = creator.get("display_name", "Unknown") if isinstance(creator, dict) else "Unknown"

    res_block = ""
    if resolution_summary:
        res_block = f"""
      <tr>
        <td style="padding:0 24px 16px;">
          <p style="margin:0 0 6px;font-size:12px;font-weight:600;color:#555;text-transform:uppercase;letter-spacing:.5px;">Resolution Notes</p>
          <div style="background:#f8f9fa;border:1px solid #e9ecef;border-radius:6px;padding:12px 16px;font-size:13px;color:#333;font-style:italic;">
            {resolution_summary}
          </div>
        </td>
      </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f2f5;padding:32px 0;">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.12);">

      <!-- Header - green for closed -->
      <tr>
        <td style="background:linear-gradient(135deg,#0d3b1e 0%,#155724 50%,#1e7e34 100%);padding:24px 24px 20px;">
          <table width="100%" cellpadding="0" cellspacing="0"><tr>
            <td>
              <p style="margin:0;font-size:11px;color:#a3d9b1;text-transform:uppercase;letter-spacing:1px;">IBM QRadar SOAR</p>
              <p style="margin:4px 0 0;font-size:20px;font-weight:700;color:#fff;">&#10003; Incident Closed</p>
            </td>
            <td align="right">
              <span style="background:{sev_color};color:#fff;font-size:12px;font-weight:700;padding:5px 14px;border-radius:20px;text-transform:uppercase;">{sev_label}</span>
            </td>
          </tr></table>
        </td>
      </tr>

      <!-- Incident name -->
      <tr>
        <td style="padding:20px 24px 12px;border-bottom:1px solid #e9ecef;">
          <p style="margin:0 0 4px;font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.5px;">Incident Name</p>
          <p style="margin:0;font-size:15px;font-weight:600;color:#1a1a2e;">{inc_name}</p>
        </td>
      </tr>

      <!-- Key metrics row 1 -->
      <tr>
        <td style="padding:16px 24px 0;">
          <table width="100%" cellpadding="0" cellspacing="0"><tr>
            <td width="33%" style="padding:0 8px 12px 0;vertical-align:top;">
              <p style="margin:0 0 3px;font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.5px;">Incident ID</p>
              <p style="margin:0;font-size:22px;font-weight:700;color:#155724;">#{inc_id}</p>
            </td>
            <td width="33%" style="padding:0 8px 12px;vertical-align:top;">
              <p style="margin:0 0 3px;font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.5px;">Severity</p>
              <p style="margin:0;font-size:15px;font-weight:600;color:{sev_color};">{sev_label} ({severity})</p>
            </td>
            <td width="33%" style="padding:0 0 12px 8px;vertical-align:top;">
              <p style="margin:0 0 3px;font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.5px;">Duration</p>
              <p style="margin:0;font-size:15px;font-weight:600;color:#333;">{duration}</p>
            </td>
          </tr></table>
        </td>
      </tr>

      <!-- Timeline + closure details -->
      <tr>
        <td style="padding:0 24px 16px;">
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8f9fa;border-radius:8px;overflow:hidden;">
            <tr style="background:#e9ecef;">
              <td style="padding:8px 14px;font-size:11px;font-weight:700;color:#555;text-transform:uppercase;letter-spacing:.5px;">Field</td>
              <td style="padding:8px 14px;font-size:11px;font-weight:700;color:#555;text-transform:uppercase;letter-spacing:.5px;">Value</td>
            </tr>
            <tr>
              <td style="padding:8px 14px;font-size:13px;color:#555;border-bottom:1px solid #e9ecef;">Opened</td>
              <td style="padding:8px 14px;font-size:13px;color:#333;border-bottom:1px solid #e9ecef;">{created_str}</td>
            </tr>
            <tr style="background:#fff;">
              <td style="padding:8px 14px;font-size:13px;color:#555;border-bottom:1px solid #e9ecef;">Closed</td>
              <td style="padding:8px 14px;font-size:13px;color:#333;border-bottom:1px solid #e9ecef;">{closed_str}</td>
            </tr>
            <tr>
              <td style="padding:8px 14px;font-size:13px;color:#555;border-bottom:1px solid #e9ecef;">Opened by</td>
              <td style="padding:8px 14px;font-size:13px;color:#333;border-bottom:1px solid #e9ecef;">{creator_name}</td>
            </tr>
            <tr style="background:#fff;">
              <td style="padding:8px 14px;font-size:13px;color:#555;border-bottom:1px solid #e9ecef;">Closed by</td>
              <td style="padding:8px 14px;font-size:13px;font-weight:600;color:#155724;border-bottom:1px solid #e9ecef;">{closer_name}</td>
            </tr>
            <tr>
              <td style="padding:8px 14px;font-size:13px;color:#555;">Resolution</td>
              <td style="padding:8px 14px;font-size:13px;font-weight:600;color:#155724;">{resolution_name}</td>
            </tr>
          </table>
        </td>
      </tr>

      {res_block}

      <tr>
        <td style="padding:8px 24px 24px;">
          <a href="{url}" style="display:inline-block;background:#155724;color:#fff;text-decoration:none;font-size:13px;font-weight:600;padding:10px 24px;border-radius:6px;">
            View in SOAR &rarr;
          </a>
        </td>
      </tr>

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

    plain = (
        f"IBM QRadar SOAR - Incident Closed\n"
        f"{'='*50}\n\n"
        f"ID:          #{inc_id}\n"
        f"Name:        {inc_name}\n"
        f"Severity:    {sev_label} ({severity})\n"
        f"Opened:      {created_str}  (by {creator_name})\n"
        f"Closed:      {closed_str}  (by {closer_name})\n"
        f"Duration:    {duration}\n"
        f"Resolution:  {resolution_name}\n"
        f"Notes:       {resolution_summary or 'N/A'}\n\n"
        f"URL: {url}\n"
    )

    return f"[SOAR] Incident Closed #{inc_id}: {inc_name[:55]}", html, plain


# ---------------------------------------------------------------------------
# Send email
# ---------------------------------------------------------------------------

def send_email(subject, html_body, plain_body):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = SMTP_FROM
    msg["To"]      = SMTP_TO
    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body,  "html",  "utf-8"))

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        server.ehlo()
        server.starttls(context=ctx)
        server.ehlo()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_FROM, [SMTP_TO], msg.as_string())


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    log.info("SOAR Email Notifier started (new + closed incidents)")
    log.info(f"Monitoring: {SOAR_URL} | Sending to: {SMTP_TO}")

    state = load_state()
    last_id        = state.get("last_id", 0)
    open_incidents = state.get("open_incidents", {})  # {str(id): {"name": ..., "create_ts": ...}}

    log.info(f"Starting from incident ID > {last_id}, tracking {len(open_incidents)} open incident(s)")

    session = None
    startup = True  # seed open_incidents on first cycle without sending new emails

    while True:
        try:
            if session is None:
                session = get_soar_session()

            incidents, need_reauth = get_open_incidents(session)

            if need_reauth:
                log.warning("Session expired, re-authenticating...")
                session = None
                continue

            # --- On startup: seed open_incidents with all currently open (no email sent) ---
            if startup:
                for i in incidents:
                    iid = str(i.get("id"))
                    if iid not in open_incidents:
                        open_incidents[iid] = {
                            "name":      i.get("name", ""),
                            "create_ts": i.get("create_date", 0)
                        }
                if open_incidents:
                    state["open_incidents"] = open_incidents
                    save_state(state)
                    log.info(f"Seeded {len(open_incidents)} currently open incident(s) for closure tracking")
                startup = False

            # --- Detect CLOSED incidents ---
            current_open_ids = {str(i.get("id")) for i in incidents}
            for inc_id_str in list(open_incidents.keys()):
                if inc_id_str not in current_open_ids:
                    # Was open, now gone from open list → fetch detail to confirm closed
                    detail = get_incident_detail(session, int(inc_id_str))
                    if detail.get("plan_status") == "C" or detail.get("end_date"):
                        history = get_incident_history(session, int(inc_id_str))
                        try:
                            subject, html_body, plain_body = build_closed_incident_email(detail, history)
                            send_email(subject, html_body, plain_body)
                            log.info(f"Closure email sent for incident #{inc_id_str}: {detail.get('name','')[:60]}")
                        except Exception as e:
                            log.error(f"Failed to send closure email for #{inc_id_str}: {e}")
                        del open_incidents[inc_id_str]
                        state["open_incidents"] = open_incidents
                        save_state(state)

            # --- Detect NEW incidents ---
            new_incidents = sorted(
                [i for i in incidents if i.get("id", 0) > last_id],
                key=lambda x: x.get("id", 0)
            )

            if new_incidents:
                log.info(f"Found {len(new_incidents)} new incident(s)")
                for incident in new_incidents:
                    inc_id = incident.get("id")
                    try:
                        subject, html_body, plain_body = build_new_incident_email(incident)
                        send_email(subject, html_body, plain_body)
                        log.info(f"New incident email sent for #{inc_id}: {incident.get('name','')[:60]}")
                    except Exception as e:
                        log.error(f"Failed to send email for incident #{inc_id}: {e}")

                    # Track this incident as open
                    open_incidents[str(inc_id)] = {
                        "name":      incident.get("name", ""),
                        "create_ts": incident.get("create_date", 0)
                    }
                    if inc_id > last_id:
                        last_id = inc_id

                state["last_id"]         = last_id
                state["open_incidents"]  = open_incidents
                save_state(state)
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
