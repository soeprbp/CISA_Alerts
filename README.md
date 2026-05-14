# CISA OT / IoT / PLC Alert Filter

This is a small Python alerting service that watches CISA sources and sends alerts only when they match OT, IoT, ICS, PLC, SCADA, HMI, RTU, DCS, industrial controller, and common vendor terms.

## What it watches

- CISA ICS Advisories RSS/XML
- CISA Cybersecurity Advisories RSS/XML
- CISA Known Exploited Vulnerabilities JSON catalog

## What it does

- Pulls CISA advisory feeds.
- Filters advisories using OT/IoT/ICS-specific keywords.
- De-duplicates alerts using a local SQLite database.
- Optionally enriches CVEs against CISA KEV.
- Sends alerts to:
  - console
  - Microsoft Teams webhook
  - email via SMTP
  - SMS via Zoom Phone or Twilio
  - Slack webhook

## Install

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env`, then run:

```bash
python cisa_ot_iot_alerts.py --once
```

For continuous polling:

```bash
python cisa_ot_iot_alerts.py --loop --interval-minutes 60
```

## Vercel

This repo also exposes a Flask app for Vercel:

- `GET /` renders the web dashboard.
- `GET /api/status` returns service/configuration status as JSON.
- `GET` or `POST /api/run` runs one poll cycle and returns the number of new matching alerts.
- `POST /run` runs one poll cycle from the dashboard.
- `vercel.json` schedules `/api/run` daily in production.

**Production URL:** https://cisa-alerts.vercel.app

Optional: set `CRON_SECRET` in Vercel. When it is set, `/api/run` requires either an
`Authorization: Bearer <CRON_SECRET>` header or `?secret=<CRON_SECRET>`.

Delivery channels are configured with environment variables:

- Teams: `TEAMS_WEBHOOK_URL`
- SMTP: `SMTP_HOST`, `SMTP_TO`, and optional SMTP auth settings
- Zoom SMS: `ZOOM_SMS_ACCOUNT_ID`, `ZOOM_SMS_CLIENT_ID`, `ZOOM_SMS_CLIENT_SECRET`,
  `ZOOM_SMS_SENDER_PHONE_NUMBER`, `ZOOM_SMS_SENDER_USER_ID`, and `ZOOM_SMS_TO`
- Twilio SMS: `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `SMS_TO`, plus either
  `TWILIO_FROM_NUMBER` or `TWILIO_MESSAGING_SERVICE_SID`
- Slack: `SLACK_WEBHOOK_URL`
- Telegram: `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`
- Telegram: `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`

Zoom SMS requires a Zoom Phone SMS-capable sender and API access to send from
that sender. If your Zoom app cannot send with server-to-server OAuth, use a
Zoom user OAuth token or Twilio SMS instead.

On Vercel, the SQLite de-duplication database is written to `/tmp` because the
deployed function filesystem is ephemeral.

### Deployment setup

This project is deployed on Vercel (Hobby plan) and connected via GitHub for CI/CD — any push to `main` triggers an automatic redeploy.

| Detail | Value |
|--------|-------|
| Vercel project | `cisa-alerts` |
| Team | `brent-soper-s-projects` |
| GitHub repo | `soeprbp/CISA_Alerts` |
| Framework preset | Python (Flask) |
| Python version | 3.12+ |
| Cron schedule | `0 9 * * *` (daily 9 AM ET) |

**Cron note:** The Hobby plan limits cron jobs to one execution per day. The schedule was changed from `0 * * * *` (hourly) to `0 9 * * *` (daily 9 AM) to comply with this limit. Upgrade to Pro for more frequent scheduling.

**To set environment variables in Vercel:**
```bash
vercel env add VAR_NAME
```

Or add them via the Vercel dashboard under Project Settings → Environment Variables.

## Suggested schedule

Run hourly with Task Scheduler, cron, systemd timer, or as a Docker/container job.

Cron example:

```cron
0 * * * * cd /opt/cisa_ot_iot_alerts && /opt/cisa_ot_iot_alerts/.venv/bin/python cisa_ot_iot_alerts.py --once
```

## Tuning

Edit `config.yaml` to add your exact PLC/OT stack vendors, products, and asset names.

Good additions for industrial environments:

- Siemens S7, TIA Portal, WinCC
- Rockwell / Allen-Bradley ControlLogix, CompactLogix, Studio 5000, FactoryTalk
- Schneider Modicon, EcoStruxure
- Omron, Mitsubishi, Phoenix Contact, WAGO, Beckhoff
- ABB, Honeywell, Yokogawa, Emerson, GE, Hitachi Energy
- Ignition, Kepware, OPC UA, Modbus, EtherNet/IP, Profinet, DNP3, BACnet

## Tooling

This project was set up and deployed using the following tools:

| Tool | Purpose |
|------|---------|
| [opencode](https://opencode.ai) | AI coding assistant — executed Vercel CLI commands, edited config, committed and pushed changes |
| [Vercel CLI](https://vercel.com/docs/cli) | Project linking, deployment, environment variable management, and deployment inspection |
| GitHub | Source hosting and CI/CD trigger for automatic Vercel deployments |
| Python 3.12+ | Runtime for the Flask application |
| uv | Python package manager for dependency resolution |
