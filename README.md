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
  - email via SMTP
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
