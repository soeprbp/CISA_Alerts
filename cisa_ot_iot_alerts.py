#!/usr/bin/env python3
"""
CISA OT / IoT / PLC alert filter.

Polls CISA RSS/XML feeds, filters for industrial/IoT/OT relevance, enriches with
CISA KEV where CVEs are present, deduplicates via SQLite, and sends alerts by
console, Slack, and/or SMTP email.
"""

from __future__ import annotations

import argparse
import email.utils
import html
import hashlib
import os
import re
import smtplib
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Iterable, Optional

import feedparser
import requests
import yaml
from dotenv import load_dotenv


DB_PATH = Path(
    os.getenv("CISA_ALERTS_DB_PATH")
    or ("/tmp/cisa_alerts_seen.sqlite3" if os.getenv("VERCEL") else "cisa_alerts_seen.sqlite3")
)
CONFIG_PATH = Path("config.yaml")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    source: str
    title: str
    link: str
    published: str
    summary: str
    matched_keywords: tuple[str, ...]
    cves: tuple[str, ...]
    kev_matches: tuple[str, ...]


@dataclass(frozen=True)
class RunSummary:
    ran_at_utc: str
    total_matches: int
    new_findings: tuple[Finding, ...]
    seen_findings: tuple[Finding, ...]
    errors: tuple[str, ...]

    @property
    def sent_count(self) -> int:
        return len(self.new_findings)


def load_config(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS seen (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            link TEXT NOT NULL,
            first_seen_utc TEXT NOT NULL
        )
        """
    )
    return conn


def normalize_text(*parts: str) -> str:
    return " ".join(p or "" for p in parts).lower()


def item_id(title: str, link: str) -> str:
    raw = f"{title}|{link}".encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()


def already_seen(conn: sqlite3.Connection, finding: Finding) -> bool:
    return conn.execute("SELECT 1 FROM seen WHERE id = ?", (item_id(finding.title, finding.link),)).fetchone() is not None


def mark_seen(conn: sqlite3.Connection, finding: Finding) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO seen (id, title, link, first_seen_utc) VALUES (?, ?, ?, ?)",
        (item_id(finding.title, finding.link), finding.title, finding.link, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def fetch_kev(kev_json_url: str) -> dict[str, dict]:
    try:
        resp = requests.get(kev_json_url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        print(f"[WARN] Could not fetch KEV catalog: {exc}", file=sys.stderr)
        return {}

    vulns = data.get("vulnerabilities", [])
    return {v.get("cveID", "").upper(): v for v in vulns if v.get("cveID")}


def parse_date(entry) -> str:
    for key in ("published", "updated", "created"):
        value = getattr(entry, key, None) or entry.get(key)
        if value:
            return value
    return datetime.now(timezone.utc).isoformat()


def find_matches(text: str, keywords: Iterable[str]) -> list[str]:
    matches = []
    for kw in keywords:
        kw_l = kw.lower().strip()
        if not kw_l:
            continue
        if kw_l in text:
            matches.append(kw)
    return sorted(set(matches), key=str.lower)


def extract_cves(text: str) -> list[str]:
    return sorted(set(m.upper() for m in CVE_RE.findall(text)))


def should_exclude(text: str, exclude_keywords: Iterable[str]) -> bool:
    return any(kw.lower().strip() and kw.lower().strip() in text for kw in exclude_keywords)


def poll_feed(feed: dict, config: dict, kev: dict[str, dict]) -> list[Finding]:
    parsed = feedparser.parse(feed["url"])
    if parsed.bozo:
        print(f"[WARN] Feed parse warning for {feed['name']}: {parsed.bozo_exception}", file=sys.stderr)

    results: list[Finding] = []
    keywords = config.get("keywords", [])
    exclude_keywords = config.get("exclude_keywords", [])
    minimum_score = int(config.get("minimum_score", 1))

    for entry in parsed.entries:
        title = entry.get("title", "").strip()
        link = entry.get("link", "").strip()
        summary = entry.get("summary", "") or entry.get("description", "")
        text = normalize_text(title, summary, link)

        if should_exclude(text, exclude_keywords):
            continue

        matches = find_matches(text, keywords)
        if len(matches) < minimum_score:
            continue

        cves = extract_cves(f"{title} {summary}")
        kev_matches = [cve for cve in cves if cve.upper() in kev]

        results.append(
            Finding(
                source=feed["name"],
                title=title,
                link=link,
                published=parse_date(entry),
                summary=re.sub(r"<[^>]+>", "", summary).strip(),
                matched_keywords=tuple(matches),
                cves=tuple(cves),
                kev_matches=tuple(kev_matches),
            )
        )
    return results


def format_finding(f: Finding) -> str:
    kev_line = f"KEV match: {', '.join(f.kev_matches)}" if f.kev_matches else "KEV match: none found"
    cve_line = f"CVEs: {', '.join(f.cves)}" if f.cves else "CVEs: none found in feed text"
    kw_line = f"Matched: {', '.join(f.matched_keywords)}"
    summary = f.summary[:900] + ("..." if len(f.summary) > 900 else "")
    return (
        f"[{f.source}] {f.title}\n"
        f"Published: {f.published}\n"
        f"{kw_line}\n"
        f"{cve_line}\n"
        f"{kev_line}\n"
        f"Link: {f.link}\n\n"
        f"{summary}"
    )


def send_slack(finding: Finding) -> None:
    webhook = os.getenv("SLACK_WEBHOOK_URL", "").strip()
    if not webhook:
        return
    text = format_finding(finding)
    resp = requests.post(webhook, json={"text": text}, timeout=30)
    resp.raise_for_status()


def send_teams(finding: Finding) -> None:
    webhook = os.getenv("TEAMS_WEBHOOK_URL", "").strip()
    if not webhook:
        return

    text = html.escape(format_finding(finding)).replace("\n", "<br>")
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": finding.title,
        "themeColor": "245B7C",
        "title": f"CISA OT/IoT Alert: {finding.title}",
        "text": text,
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "Open advisory",
                "targets": [{"os": "default", "uri": finding.link}],
            }
        ],
    }
    resp = requests.post(webhook, json=payload, timeout=30)
    resp.raise_for_status()


def send_email(finding: Finding) -> None:
    host = os.getenv("SMTP_HOST", "").strip()
    if not host:
        return

    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "").strip()
    mail_from = os.getenv("SMTP_FROM", username or "cisa-alerts@example.com").strip()
    mail_to = os.getenv("SMTP_TO", "").strip()
    starttls = os.getenv("SMTP_STARTTLS", "true").lower() in ("1", "true", "yes")

    if not mail_to:
        print("[WARN] SMTP_HOST set but SMTP_TO missing; skipping email", file=sys.stderr)
        return

    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = mail_to
    msg["Date"] = email.utils.formatdate(localtime=True)
    kev_prefix = "[CISA OT/IoT KEV] " if finding.kev_matches else "[CISA OT/IoT] "
    msg["Subject"] = kev_prefix + finding.title[:140]
    msg.set_content(format_finding(finding))

    with smtplib.SMTP(host, port, timeout=30) as smtp:
        if starttls:
            smtp.starttls()
        if username and password:
            smtp.login(username, password)
        smtp.send_message(msg)


def split_recipients(value: str) -> list[str]:
    return [part.strip() for part in re.split(r"[;,]", value) if part.strip()]


def sms_body(finding: Finding, max_chars: int = 480) -> str:
    body = f"CISA OT/IoT alert: {finding.title}\n{finding.link}"
    if len(body) <= max_chars:
        return body
    return f"CISA OT/IoT alert: {finding.title[: max_chars - len(finding.link) - 28]}...\n{finding.link}"


def zoom_access_token() -> str:
    token = os.getenv("ZOOM_SMS_ACCESS_TOKEN", "").strip()
    if token:
        return token

    account_id = os.getenv("ZOOM_SMS_ACCOUNT_ID", "").strip()
    client_id = os.getenv("ZOOM_SMS_CLIENT_ID", "").strip()
    client_secret = os.getenv("ZOOM_SMS_CLIENT_SECRET", "").strip()
    if not account_id or not client_id or not client_secret:
        return ""

    resp = requests.post(
        "https://zoom.us/oauth/token",
        params={"grant_type": "account_credentials", "account_id": account_id},
        auth=(client_id, client_secret),
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("access_token", "")


def send_zoom_sms(finding: Finding) -> None:
    recipients = split_recipients(os.getenv("ZOOM_SMS_TO", ""))
    sender_phone = os.getenv("ZOOM_SMS_SENDER_PHONE_NUMBER", "").strip()
    sender_user_id = os.getenv("ZOOM_SMS_SENDER_USER_ID", "").strip()
    if not recipients or not sender_phone or not sender_user_id:
        return

    token = zoom_access_token()
    if not token:
        print("[WARN] Zoom SMS configured but no access token settings are available; skipping Zoom SMS", file=sys.stderr)
        return

    payload = {
        "sender": {
            "phone_number": sender_phone,
            "user_id": sender_user_id,
        },
        "to_members": [{"phone_number": recipient} for recipient in recipients],
        "message": sms_body(finding),
    }
    resp = requests.post(
        "https://api.zoom.us/v2/phone/sms/messages",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        json=payload,
        timeout=30,
    )
    resp.raise_for_status()


def send_sms(finding: Finding) -> None:
    account_sid = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
    auth_token = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
    recipients = split_recipients(os.getenv("SMS_TO", ""))
    if not account_sid or not auth_token or not recipients:
        return

    from_number = os.getenv("TWILIO_FROM_NUMBER", "").strip()
    messaging_service_sid = os.getenv("TWILIO_MESSAGING_SERVICE_SID", "").strip()
    if not from_number and not messaging_service_sid:
        print("[WARN] Twilio SMS configured but no sender number or messaging service set; skipping SMS", file=sys.stderr)
        return

    body = sms_body(finding)
    url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"

    for recipient in recipients:
        data = {"To": recipient, "Body": body}
        if messaging_service_sid:
            data["MessagingServiceSid"] = messaging_service_sid
        else:
            data["From"] = from_number

        resp = requests.post(url, data=data, auth=(account_sid, auth_token), timeout=30)
        resp.raise_for_status()


def alert(finding: Finding) -> None:
    print("=" * 88)
    print(format_finding(finding))
    print()
    delivery_errors: list[str] = []
    for channel, sender in (
        ("Slack", send_slack),
        ("Teams", send_teams),
        ("SMTP", send_email),
        ("Zoom SMS", send_zoom_sms),
        ("Twilio SMS", send_sms),
    ):
        try:
            sender(finding)
        except Exception as exc:
            delivery_errors.append(f"{channel}: {exc}")

    if delivery_errors:
        raise RuntimeError("; ".join(delivery_errors))


def run_poll(config: dict, *, send_alerts: bool = True, update_seen: bool = True) -> RunSummary:
    conn = db_connect()
    kev = fetch_kev(config.get("kev_json_url", ""))
    new_findings: list[Finding] = []
    seen_findings: list[Finding] = []
    errors: list[str] = []
    total_matches = 0

    for feed in config.get("feeds", []):
        try:
            findings = poll_feed(feed, config, kev)
        except Exception as exc:
            errors.append(f"{feed.get('name', 'Unknown feed')}: {exc}")
            continue

        for finding in findings:
            total_matches += 1
            if already_seen(conn, finding):
                seen_findings.append(finding)
                continue

            try:
                if send_alerts:
                    alert(finding)
                if update_seen:
                    mark_seen(conn, finding)
                new_findings.append(finding)
            except Exception as exc:
                errors.append(f"{finding.title}: {exc}")

    summary = RunSummary(
        ran_at_utc=datetime.now(timezone.utc).isoformat(),
        total_matches=total_matches,
        new_findings=tuple(new_findings),
        seen_findings=tuple(seen_findings),
        errors=tuple(errors),
    )

    print(f"[OK] New matching alerts sent: {summary.sent_count}")
    for error in summary.errors:
        print(f"[ERROR] {error}", file=sys.stderr)
    return summary


def run_once(config: dict) -> int:
    return run_poll(config).sent_count


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="CISA OT/IoT/PLC alert filter")
    parser.add_argument("--config", default=str(CONFIG_PATH), help="Path to config.yaml")
    parser.add_argument("--once", action="store_true", help="Run one poll cycle")
    parser.add_argument("--loop", action="store_true", help="Run forever")
    parser.add_argument("--interval-minutes", type=int, default=60, help="Polling interval for --loop")
    args = parser.parse_args()

    config = load_config(Path(args.config))

    if not args.once and not args.loop:
        parser.error("Use --once or --loop")

    if args.once:
        run_once(config)
        return 0

    while True:
        try:
            run_once(config)
        except Exception as exc:
            print(f"[ERROR] Poll cycle failed: {exc}", file=sys.stderr)
        time.sleep(max(args.interval_minutes, 1) * 60)


if __name__ == "__main__":
    raise SystemExit(main())
