# CyberShield-AI
A Python-based defensive cybersecurity project
that analyses login activity and detects possible
brute-force attacks.

## Features
- CSV login log analysis
- Failed login monitoring
- Time-window-based detection
- Security alert generation
- Automatic report creation

## Technology
- Python
- CSV
- Datetime
- Git and GitHub

## Detection Rule
Detects 5 or more failed login attempts
from the same IP address within 10 minutes.

## How to Run

1. Install Python 3.12 or newer.
2. Clone this repository.
3. Run:

   python detector.py

## Disclaimer
This project uses simulated security logs
for educational and defensive purposes.
An alert is an indicator, not proof of an attack.
