# Log Analyzer 

# Project Overview
This project analyzes system log files and detects suspicious activities such as failed login attempts, errors and unauthorized access.

# Features
- Detects suspicious keywords in logs
- Extracts IP addresses from suspicious events
- Counts attack attempts per IP
- Detects possible brute-force attacks

# Technologies Used:
Python

# How It Works
1. The script reads a log file.
2. It scans for suspicious keywords.
3. It extracts IP addresses from suspicious lines.
4. It counts how many attempts each IP makes.
5. If an IP has multiple attempts it triggers a possible attack alert.

# Example Output
Suspicious activities found:
Failed login attempt from 45.23.12.10

Total suspicious events: 12

IP Activity Summary:
45.23.12.10 -> 4 attempts

Possible Attacks:
ALERT: Possible brute force attack from 45.23.12.10
