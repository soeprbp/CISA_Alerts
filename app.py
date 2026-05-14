from __future__ import annotations

import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template_string, request
from markupsafe import escape

load_dotenv()

from cisa_ot_iot_alerts import CONFIG_PATH, Finding, RunSummary, load_config, run_poll


app = Flask(__name__)
app.json.sort_keys = False


DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CISA Alerts</title>
  <style>
    :root {
      --bg: #f5f7fa;
      --panel: #ffffff;
      --ink: #18212b;
      --muted: #687385;
      --line: #dbe2ea;
      --blue: #245b7c;
      --green: #1f7a4d;
      --amber: #a65f00;
      --red: #a33838;
      --shadow: 0 14px 40px rgba(25, 35, 50, 0.08);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--ink);
      font-family: Arial, Helvetica, sans-serif;
      line-height: 1.5;
    }

    a { color: var(--blue); }

    .topbar {
      display: flex;
      justify-content: space-between;
      gap: 24px;
      align-items: center;
      padding: 28px clamp(18px, 4vw, 48px);
      background: #ffffff;
      border-bottom: 1px solid var(--line);
    }

    .eyebrow {
      margin: 0 0 4px;
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
    }

    h1, h2, h3, p { margin-top: 0; }

    h1 {
      margin-bottom: 0;
      font-size: clamp(28px, 5vw, 44px);
      line-height: 1.05;
    }

    h2 {
      margin-bottom: 12px;
      font-size: 20px;
    }

    h3 {
      margin-bottom: 6px;
      font-size: 16px;
    }

    .pill {
      display: inline-flex;
      align-items: center;
      min-height: 34px;
      padding: 6px 10px;
      border: 1px solid var(--line);
      border-radius: 999px;
      color: var(--green);
      background: #f1f8f4;
      font-size: 14px;
      font-weight: 700;
      white-space: nowrap;
    }

    main {
      width: min(1180px, calc(100% - 36px));
      margin: 28px auto 48px;
    }

    .metrics {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 20px;
    }

    .metric,
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }

    .metric {
      padding: 16px;
      min-height: 96px;
    }

    .metric .label {
      margin-bottom: 8px;
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
    }

    .metric .value {
      margin: 0;
      font-size: 24px;
      font-weight: 800;
    }

    .layout {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 340px;
      gap: 20px;
      align-items: start;
    }

    .panel {
      padding: 20px;
      margin-bottom: 20px;
    }

    .panel-header {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: start;
      margin-bottom: 14px;
    }

    .muted {
      color: var(--muted);
    }

    .run-form {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: end;
    }

    label {
      display: grid;
      gap: 6px;
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
    }

    input {
      width: min(320px, 100%);
      min-height: 42px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 10px;
      font: inherit;
    }

    button {
      min-height: 42px;
      border: 0;
      border-radius: 6px;
      padding: 9px 14px;
      background: var(--blue);
      color: #ffffff;
      font: inherit;
      font-weight: 800;
      cursor: pointer;
    }

    button:hover { filter: brightness(0.95); }

    .status-grid {
      display: grid;
      gap: 10px;
    }

    .status-row {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--line);
    }

    .status-row:last-child {
      padding-bottom: 0;
      border-bottom: 0;
    }

    .enabled { color: var(--green); font-weight: 800; }
    .disabled { color: var(--amber); font-weight: 800; }
    .error { color: var(--red); font-weight: 800; }

    .alert-box {
      margin-top: 16px;
      padding: 14px;
      border: 1px solid #cfe5d8;
      border-radius: 8px;
      background: #f3fbf6;
    }

    .alert-box.error-box {
      border-color: #efc9c9;
      background: #fff6f6;
    }

    .finding {
      padding: 16px 0;
      border-top: 1px solid var(--line);
    }

    .finding:first-of-type { border-top: 0; }

    .finding-title {
      margin-bottom: 8px;
      font-weight: 800;
    }

    .meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 10px;
    }

    .tag {
      display: inline-flex;
      align-items: center;
      max-width: 100%;
      min-height: 26px;
      padding: 3px 8px;
      border-radius: 999px;
      background: #edf2f7;
      color: #334155;
      font-size: 12px;
      font-weight: 700;
    }

    .summary {
      color: #3f4a59;
      overflow-wrap: anywhere;
    }

    .feed-list {
      display: grid;
      gap: 12px;
      margin: 0;
      padding: 0;
      list-style: none;
    }

    .feed-list li {
      padding-bottom: 12px;
      border-bottom: 1px solid var(--line);
    }

    .feed-list li:last-child {
      padding-bottom: 0;
      border-bottom: 0;
    }

    .feed-url {
      display: block;
      color: var(--muted);
      font-size: 13px;
      overflow-wrap: anywhere;
    }

    @media (max-width: 860px) {
      .topbar { align-items: flex-start; flex-direction: column; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .layout { grid-template-columns: 1fr; }
    }

    @media (max-width: 520px) {
      main { width: min(100% - 24px, 1180px); }
      .metrics { grid-template-columns: 1fr; }
      .panel-header { flex-direction: column; }
      .run-form { display: grid; }
      input, button { width: 100%; }
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div>
      <p class="eyebrow">Operational technology alerting</p>
      <h1>CISA Alerts</h1>
    </div>
    <span class="pill">Hourly polling</span>
  </header>

  <main>
    <section class="metrics" aria-label="Service metrics">
      <div class="metric">
        <p class="label">Feeds</p>
        <p class="value">{{ feeds|length }}</p>
      </div>
      <div class="metric">
        <p class="label">Keywords</p>
        <p class="value">{{ keyword_count }}</p>
      </div>
      <div class="metric">
        <p class="label">Minimum Score</p>
        <p class="value">{{ minimum_score }}</p>
      </div>
      <div class="metric">
        <p class="label">Cron</p>
        <p class="value">0 * * * *</p>
      </div>
    </section>

    <div class="layout">
      <section>
        <div class="panel">
          <div class="panel-header">
            <div>
              <h2>Poll Runner</h2>
              <p class="muted">Last loaded {{ loaded_at_utc }}</p>
            </div>
          </div>
          <form class="run-form" method="post" action="/run">
            {% if secret_required %}
            <label>
              Run secret
              <input name="secret" type="password" autocomplete="current-password">
            </label>
            {% endif %}
            <button type="submit">Run Poll Now</button>
          </form>

          {% if error %}
          <div class="alert-box error-box">
            <strong class="error">Run failed</strong>
            <p>{{ error }}</p>
          </div>
          {% endif %}

          {% if result %}
          <div class="alert-box">
            <strong>Run complete</strong>
            <p>{{ result.sent_count }} new alerts from {{ result.total_matches }} matching feed items.</p>
            {% if result.errors %}
            <p class="error">{{ result.errors|length }} delivery or feed errors were logged.</p>
            {% endif %}
          </div>
          {% endif %}
        </div>

        {% if result %}
        <div class="panel">
          <h2>New Alerts</h2>
          {% if result.new_findings %}
            {% for finding in result.new_findings %}
              {{ finding_card(finding)|safe }}
            {% endfor %}
          {% else %}
            <p class="muted">No new matching alerts in this run.</p>
          {% endif %}
        </div>

        <div class="panel">
          <h2>Already Seen</h2>
          {% if result.seen_findings %}
            {% for finding in result.seen_findings[:10] %}
              {{ finding_card(finding)|safe }}
            {% endfor %}
          {% else %}
            <p class="muted">No previously seen matching alerts in this run.</p>
          {% endif %}
        </div>
        {% endif %}
      </section>

      <aside>
        <div class="panel">
          <h2>Delivery</h2>
          <div class="status-grid">
            {% for channel in channels %}
            <div class="status-row">
              <span>{{ channel.name }}</span>
              <span class="{{ 'enabled' if channel.enabled else 'disabled' }}">
                {{ 'Enabled' if channel.enabled else 'Not set' }}
              </span>
            </div>
            {% endfor %}
          </div>
        </div>

        <div class="panel">
          <h2>Feeds</h2>
          <ul class="feed-list">
            {% for feed in feeds %}
            <li>
              <strong>{{ feed.name }}</strong>
              <span class="feed-url">{{ feed.url }}</span>
            </li>
            {% endfor %}
          </ul>
        </div>
      </aside>
    </div>
  </main>
</body>
</html>
"""


def _secret_required() -> bool:
    return bool(os.getenv("CRON_SECRET", "").strip())


def _request_is_authorized() -> bool:
    secret = os.getenv("CRON_SECRET", "").strip()
    if not secret:
        return True

    auth_header = request.headers.get("Authorization", "")
    query_secret = request.args.get("secret", "")
    form_secret = request.form.get("secret", "")

    return auth_header == f"Bearer {secret}" or query_secret == secret or form_secret == secret


def _finding_to_dict(finding: Finding) -> dict:
    return {
        "source": finding.source,
        "title": finding.title,
        "link": finding.link,
        "published": finding.published,
        "summary": finding.summary,
        "matched_keywords": list(finding.matched_keywords),
        "cves": list(finding.cves),
        "kev_matches": list(finding.kev_matches),
    }


def _summary_to_dict(summary: RunSummary) -> dict:
    return {
        "ok": not summary.errors,
        "ran_at_utc": summary.ran_at_utc,
        "total_matches": summary.total_matches,
        "new_alerts_sent": summary.sent_count,
        "new_findings": [_finding_to_dict(finding) for finding in summary.new_findings],
        "seen_count": len(summary.seen_findings),
        "errors": list(summary.errors),
    }


def _channels() -> list[dict]:
    return [
        {"name": "Console", "enabled": True},
        {"name": "Microsoft Teams", "enabled": bool(os.getenv("TEAMS_WEBHOOK_URL", "").strip())},
        {"name": "Slack", "enabled": bool(os.getenv("SLACK_WEBHOOK_URL", "").strip())},
        {
            "name": "SMTP",
            "enabled": bool(os.getenv("SMTP_HOST", "").strip() and os.getenv("SMTP_TO", "").strip()),
        },
        {
            "name": "Twilio SMS",
            "enabled": bool(
                os.getenv("TWILIO_ACCOUNT_SID", "").strip()
                and os.getenv("TWILIO_AUTH_TOKEN", "").strip()
                and os.getenv("SMS_TO", "").strip()
            ),
        },
        {
            "name": "Zoom SMS",
            "enabled": bool(
                os.getenv("ZOOM_SMS_TO", "").strip()
                and os.getenv("ZOOM_SMS_SENDER_PHONE_NUMBER", "").strip()
                and os.getenv("ZOOM_SMS_SENDER_USER_ID", "").strip()
                and (
                    os.getenv("ZOOM_SMS_ACCESS_TOKEN", "").strip()
                    or (
                        os.getenv("ZOOM_SMS_ACCOUNT_ID", "").strip()
                        and os.getenv("ZOOM_SMS_CLIENT_ID", "").strip()
                        and os.getenv("ZOOM_SMS_CLIENT_SECRET", "").strip()
                    )
                )
            ),
        },
    ]


def _finding_card(finding: Finding) -> str:
    tags = "".join(f'<span class="tag">{escape(tag)}</span>' for tag in finding.matched_keywords[:8])
    cves = ", ".join(finding.cves) if finding.cves else "No CVEs in feed text"
    kev = ", ".join(finding.kev_matches) if finding.kev_matches else "No KEV match"
    summary = finding.summary[:500] + ("..." if len(finding.summary) > 500 else "")
    return f"""
    <article class="finding">
      <div class="finding-title"><a href="{escape(finding.link)}">{escape(finding.title)}</a></div>
      <div class="meta">
        <span class="tag">{escape(finding.source)}</span>
        <span class="tag">{escape(finding.published)}</span>
        <span class="tag">{escape(cves)}</span>
        <span class="tag">{escape(kev)}</span>
      </div>
      <div class="meta">{tags}</div>
      <p class="summary">{escape(summary)}</p>
    </article>
    """


def _render_dashboard(result: RunSummary | None = None, error: str | None = None, status_code: int = 200):
    config = load_config(CONFIG_PATH)
    html = render_template_string(
        DASHBOARD_TEMPLATE,
        channels=_channels(),
        error=error,
        feeds=config.get("feeds", []),
        finding_card=_finding_card,
        keyword_count=len(config.get("keywords", [])),
        loaded_at_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        minimum_score=config.get("minimum_score", 1),
        result=result,
        secret_required=_secret_required(),
    )
    return html, status_code


@app.get("/")
def dashboard():
    return _render_dashboard()


@app.post("/run")
def run_from_dashboard():
    if not _request_is_authorized():
        return _render_dashboard(error="Unauthorized", status_code=401)

    try:
        summary = run_poll(load_config(CONFIG_PATH))
    except Exception as exc:
        return _render_dashboard(error=str(exc), status_code=500)

    status_code = 500 if summary.errors else 200
    return _render_dashboard(result=summary, status_code=status_code)


@app.get("/api/status")
def api_status():
    config = load_config(CONFIG_PATH)
    return jsonify(
        {
            "ok": True,
            "feeds": config.get("feeds", []),
            "keyword_count": len(config.get("keywords", [])),
            "minimum_score": config.get("minimum_score", 1),
            "channels": _channels(),
            "secret_required": _secret_required(),
        }
    )


@app.route("/api/run", methods=["GET", "POST"])
def api_run():
    if not _request_is_authorized():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    try:
        summary = run_poll(load_config(CONFIG_PATH))
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500

    status_code = 500 if summary.errors else 200
    return jsonify(_summary_to_dict(summary)), status_code
