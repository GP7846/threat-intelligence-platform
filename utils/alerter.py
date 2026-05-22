"""
utils/alerter.py — Multi-channel SOC alerting.
Supports Discord webhooks and Slack webhooks.
Silently skips if no webhook URL is configured.
"""

from __future__ import annotations

import requests
from utils.logger import alert_logger
from config.settings import DISCORD_WEBHOOK_URL, SLACK_WEBHOOK_URL


def send_alert(ip_address: str, threat_type: str, risk_score: int = 0):
    """Dispatch block alerts to all configured channels."""
    if DISCORD_WEBHOOK_URL:
        _send_discord(ip_address, threat_type, risk_score)
    if SLACK_WEBHOOK_URL:
        _send_slack(ip_address, threat_type, risk_score)


def _send_discord(ip_address: str, threat_type: str, risk_score: int):
    """Send a rich embed alert to a Discord SOC channel."""
    color = 0xFF0000 if risk_score >= 85 else 0xFF8C00  # red / orange

    payload = {
        "content": "🚨 **HIGH-RISK THREAT BLOCKED**",
        "embeds": [
            {
                "title": f"🔴 Target Dropped: `{ip_address}`",
                "description": (
                    f"The kernel firewall has automatically intercepted "
                    f"and dropped a **{threat_type}** node."
                ),
                "color": color,
                "fields": [
                    {"name": "Risk Score", "value": f"`{risk_score}/100`", "inline": True},
                    {"name": "Threat Type", "value": f"`{threat_type}`",   "inline": True},
                    {"name": "Action",      "value": "`iptables DROP`",    "inline": True},
                ],
                "footer": {"text": "TIP — Threat Intelligence Platform v2.0"},
            }
        ],
    }

    try:
        resp = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
        if resp.status_code == 204:
            alert_logger.info(f"[Alert][Discord] Notified SOC for {ip_address}.")
        else:
            alert_logger.error(
                f"[Alert][Discord] Unexpected status {resp.status_code} for {ip_address}."
            )
    except Exception as exc:
        alert_logger.error(f"[Alert][Discord] Failed to send webhook: {exc}")


def _send_slack(ip_address: str, threat_type: str, risk_score: int):
    """Send a Slack block-kit alert to a SOC channel."""
    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🚨 Threat Blocked by TIP"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*IP Address:*\n`{ip_address}`"},
                    {"type": "mrkdwn", "text": f"*Threat Type:*\n`{threat_type}`"},
                    {"type": "mrkdwn", "text": f"*Risk Score:*\n`{risk_score}/100`"},
                    {"type": "mrkdwn", "text": "*Action:*\n`iptables DROP`"},
                ],
            },
        ]
    }

    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        if resp.status_code == 200:
            alert_logger.info(f"[Alert][Slack] Notified SOC for {ip_address}.")
        else:
            alert_logger.error(
                f"[Alert][Slack] Unexpected status {resp.status_code} for {ip_address}."
            )
    except Exception as exc:
        alert_logger.error(f"[Alert][Slack] Failed to send webhook: {exc}")
