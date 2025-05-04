from colorama import Fore, Style
import requests
from src.utils import log_alert, load_config

def alert_suspicious_activity(message):
    config = load_config()

    print(Fore.RED + "[ALERT]" + Style.RESET_ALL, message)
    log_alert(message)

    if config.get("enable_webhook") and config.get("webhook_url"):
        payload = {"text": f"[ALERT] {message}"}
        try:
            requests.post(config["webhook_url"], json=payload, timeout=5)
        except Exception as e:
            print(Fore.YELLOW + "[!] Failed to send webhook alert" + Style.RESET_ALL)
