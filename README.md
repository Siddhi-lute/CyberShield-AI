# CyberShield AI - Intelligent Login Threat Detection System

CyberShield AI is a Python-based defensive cybersecurity project that analyses simulated login activity and identifies suspicious login patterns using predefined detection rules.

## Features

- CSV-based login activity analysis
- Detection of repeated failed login attempts from the same IP address
- Detection of repeated failed attempts for the same username
- Identification of successful logins after repeated failures
- Detection of usernames associated with multiple IP addresses
- Unusual login-hour detection
- Rapid login activity detection
- Risk scoring and severity classification
- Security dashboard generation
- Automatic security report creation

## Technologies Used

- Python 3
- CSV
- Datetime
- Git and GitHub

## Detection Rules

The system uses predefined rules to identify suspicious login behaviour:

1. Five or more failed login attempts from the same IP within 10 minutes.
2. Five or more failed login attempts for the same username within 10 minutes.
3. Successful login after repeated failed attempts.
4. One username appearing from multiple IP addresses.
5. Login activity before 6:00 AM or at/after 10:00 PM.
6. Four or more login events from the same IP within 60 seconds.

## Risk Scoring

Each detected alert receives a risk score and severity level.

| Severity | Risk Score |
|---|---:|
| LOW | Below 20 |
| MEDIUM | 20-39 |
| HIGH | 40-59 |
| CRITICAL | 60 or above |

## Project Structure

```text
CyberShield-AI/
├── data/
│   └── sample_logs.csv
├── reports/
│   ├── security_alerts.txt
│   └── dashboard_summary.txt
├── detector.py
├── README.md
└── .gitignore
```

## How to Run

1. Install Python 3.12 or newer.
2. Clone this repository.
3. Open the project folder in a terminal.
4. Run:

```bash
python detector.py
```

The system displays the dashboard and detected alerts in the terminal and saves the reports in the `reports` folder.

## Disclaimer

This project uses simulated login data for educational and defensive cybersecurity purposes. Detection rules and risk scores are illustrative. An alert is an indicator of suspicious activity, not proof of an attack.