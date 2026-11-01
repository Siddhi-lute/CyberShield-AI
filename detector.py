
import csv
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

# Project file locations
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "data" / "sample_logs.csv"
REPORT_DIR = BASE_DIR / "reports"
REPORT_FILE = REPORT_DIR / "security_alerts.txt"

# Detection settings
FAILURE_THRESHOLD = 5
TIME_WINDOW_MINUTES = 10


def load_logs():
    """Read and validate simulated login events."""
    events = []

    with LOG_FILE.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        required = {"timestamp", "username", "ip_address", "status"}

        if not required.issubset(reader.fieldnames or []):
            raise ValueError("Missing required CSV columns.")

        for line_number, row in enumerate(reader, start=2):
            try:
                timestamp = datetime.fromisoformat(row["timestamp"])
                username = row["username"].strip()
                ip = row["ip_address"].strip()
                status = row["status"].strip().upper()

                if not username or not ip:
                    raise ValueError("Empty username or IP.")

                if status not in {"SUCCESS", "FAILED"}:
                    raise ValueError("Invalid login status.")

                events.append({
                    "timestamp": timestamp,
                    "username": username,
                    "ip": ip,
                    "status": status
                })

            except (ValueError, TypeError) as error:
                print(f"Skipping row {line_number}: {error}")

    return sorted(events, key=lambda event: event["timestamp"])


def detect_threats(events):
    """Flag IP addresses with repeated failed login attempts."""
    failures = defaultdict(deque)
    alerts = []

    window = timedelta(minutes=TIME_WINDOW_MINUTES)

    for event in events:
        ip = event["ip"]
        timestamp = event["timestamp"]

        attempts = failures[ip]

        # Remove attempts outside the time window
        while attempts and timestamp - attempts[0] > window:
            attempts.popleft()

        if event["status"] == "FAILED":
            attempts.append(timestamp)

            if len(attempts) == FAILURE_THRESHOLD:
                alerts.append({
                    "time": timestamp.isoformat(),
                    "ip": ip,
                    "type": "Possible brute-force activity",
                    "details": (
                        f"{len(attempts)} failed attempts "
                        f"within {TIME_WINDOW_MINUTES} minutes"
                    )
                })

    return alerts


def save_report(alerts):
    """Save detected alerts to a text report."""
    REPORT_DIR.mkdir(exist_ok=True)

    with REPORT_FILE.open("w", encoding="utf-8") as file:
        file.write("CYBERSHIELD AI - SECURITY REPORT\n")
        file.write("=" * 40 + "\n\n")

        if not alerts:
            file.write("No suspicious login patterns detected.\n")

        for number, alert in enumerate(alerts, start=1):
            file.write(f"Alert #{number}\n")
            file.write(f"Time: {alert['time']}\n")
            file.write(f"IP: {alert['ip']}\n")
            file.write(f"Type: {alert['type']}\n")
            file.write(f"Details: {alert['details']}\n")
            file.write("-" * 40 + "\n")

    print(f"\nReport saved to: {REPORT_FILE}")


def main():
    print("\nCYBERSHIELD AI - LOGIN THREAT DETECTOR")
    print("=" * 45)

    events = load_logs()
    alerts = detect_threats(events)

    print(f"Total login events analysed: {len(events)}")
    print(f"Security alerts generated: {len(alerts)}")

    for alert in alerts:
        print("\n[ALERT]")
        print("IP:", alert["ip"])
        print("Threat:", alert["type"])
        print("Details:", alert["details"])

    save_report(alerts)


if __name__ == "__main__":
    main()
