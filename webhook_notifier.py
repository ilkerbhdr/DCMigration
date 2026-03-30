"""Teams / Slack / Generic Webhook bildirim modülü.

Webhook yapılandırmaları DB'den okunur (database.py).
send_notification ve test_webhook fonksiyonları dışarıdan çağrılır.
"""
import threading

import requests


def send_notification(title, message, color="warning"):
    """Tüm aktif webhook'lara bildirim gönderir (non-blocking).

    DB'den webhook listesini okur.
    """
    try:
        from database import db_get_webhooks
        hooks = db_get_webhooks()
    except Exception:
        return

    active = [h for h in hooks if h.get("enabled", True)]
    if not active:
        return

    for hook in active:
        thread = threading.Thread(
            target=_send_single,
            args=(hook, title, message, color),
            daemon=True,
        )
        thread.start()


def _send_single(hook, title, message, color):
    try:
        hook_type = hook.get("type", "generic")
        url = hook["url"]

        if hook_type == "teams":
            payload = _build_teams_payload(title, message, color)
        elif hook_type == "slack":
            payload = _build_slack_payload(title, message, color)
        else:
            payload = _build_generic_payload(title, message)

        requests.post(url, json=payload, timeout=10, headers={"Content-Type": "application/json"})
    except Exception:
        pass


def _build_teams_payload(title, message, color):
    color_map = {"good": "Good", "warning": "Warning", "danger": "Attention"}
    style = color_map.get(color, "Default")
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard", "version": "1.4",
                "body": [
                    {"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "style": style},
                    {"type": "TextBlock", "text": message, "wrap": True},
                ],
            },
        }],
    }


def _build_slack_payload(title, message, color):
    color_hex = {"good": "#36a64f", "warning": "#ff9900", "danger": "#dc2626"}.get(color, "#2563eb")
    return {
        "attachments": [{
            "color": color_hex, "title": title, "text": message, "footer": "Port Mapping Tool",
        }],
    }


def _build_generic_payload(title, message):
    return {"title": title, "message": message}


def test_webhook(name):
    """Belirli bir webhook'u test eder. Returns (success, detail)."""
    try:
        from database import db_get_webhooks
        hooks = db_get_webhooks()
    except Exception as e:
        return False, f"DB hatası: {str(e)}"

    hook = next((h for h in hooks if h["name"] == name), None)
    if not hook:
        return False, "Webhook bulunamadı"

    try:
        hook_type = hook.get("type", "generic")
        if hook_type == "teams":
            payload = _build_teams_payload("Test Bildirimi", "Port Mapping webhook testi başarılı!", "good")
        elif hook_type == "slack":
            payload = _build_slack_payload("Test Bildirimi", "Port Mapping webhook testi başarılı!", "good")
        else:
            payload = _build_generic_payload("Test Bildirimi", "Port Mapping webhook testi başarılı!")

        resp = requests.post(hook["url"], json=payload, timeout=10, headers={"Content-Type": "application/json"})
        if resp.status_code < 300:
            return True, f"Başarılı (HTTP {resp.status_code})"
        return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except requests.Timeout:
        return False, "Zaman aşımı (10 sn)"
    except Exception as e:
        return False, str(e)
