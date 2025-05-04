import yaml

def load_config(path="config/settings.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def log_alert(message):
    with open("logs/alerts.log", "a") as log_file:
        log_file.write(message + "\n")
