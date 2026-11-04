
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
    """Detect suspicious patterns in simulated login events."""

    ip_failures = defaultdict(deque)
    username_failures = defaultdict(deque)
    username_ips = defaultdict(set)

    alerts = []
    window = timedelta(minutes=TIME_WINDOW_MINUTES)

    for event in events:
        ip = event["ip"]
        username = event["username"]
        timestamp = event["timestamp"]
        status = event["status"]

        # Track IP addresses used by each username
        username_ips[username].add(ip)

        # 1. IP-based failed login detection
        ip_attempts = ip_failures[ip]

        while ip_attempts and timestamp - ip_attempts[0] > window:
            ip_attempts.popleft()

        # 2. Username-based failed login detection
        user_attempts = username_failures[username]

        while user_attempts and timestamp - user_attempts[0] > window:
            user_attempts.popleft()

        if status == "FAILED":
            ip_attempts.append(timestamp)
            user_attempts.append(timestamp)

            if len(ip_attempts) == FAILURE_THRESHOLD:
                alerts.append({
                    "time": timestamp.isoformat(),
                    "ip": ip,
                    "type": "Repeated failures from one IP",
                    "details": (
                        f"{len(ip_attempts)} failed attempts "
                        f"within {TIME_WINDOW_MINUTES} minutes"
                    )
                })

            if len(user_attempts) == FAILURE_THRESHOLD:
                alerts.append({
                    "time": timestamp.isoformat(),
                    "ip": ip,
                    "type": "Repeated failures for one username",
                    "details": (
                        f"Username '{username}' had "
                        f"{len(user_attempts)} failed attempts "
                        f"within {TIME_WINDOW_MINUTES} minutes"
                    )
                })

        # 3. Successful login following repeated failures
        elif status == "SUCCESS":
            if len(ip_attempts) >= 3:
                alerts.append({
                    "time": timestamp.isoformat(),
                    "ip": ip,
                    "type": "Success after repeated failures",
                    "details": (
                        f"Username '{username}' logged in successfully "
                        f"after {len(ip_attempts)} recent failures "
                        f"from this IP"
                    )
                })

    # 4. Multiple-IP analysis
    for username, ips in username_ips.items():
        if len(ips) >= 3:
            alerts.append({
                "time": "End of analysis",
                "ip": ", ".join(sorted(ips)),
                "type": "Username associated with multiple IPs",
                "details": (
                    f"Username '{username}' appeared from "
                    f"{len(ips)} different IP addresses"
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
