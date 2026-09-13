# Linux Security Auditor

A Bash-based Linux security auditing tool that performs automated checks for common system security issues, file permissions, user privileges, authentication activity, network exposure, and system configuration.

## Overview

Linux Security Auditor is a lightweight security auditing script designed to quickly assess the security posture of a Linux system.

The tool performs 15 core security checks and reports findings using severity levels, finding IDs, recommendations, and an overall risk score.

## Features

- System information collection
- Firewall status check
- SSH server detection
- UID 0 account verification
- User password status check
- Sudo privilege review
- World-writable file detection
- SUID file detection
- Network-facing port detection
- Available system update detection
- Cron job review
- Failed authentication detection
- System error detection
- Password aging check
- World-writable directory detection
- Severity classification
- Security recommendations
- Risk score calculation
- JSON report generation

## Security Checks

| ID | Check | Category |
|---|---|---|
| NET-001 | Firewall Status | Network Security |
| NET-002 | SSH Server | Network Security |
| AUTH-001 | UID 0 Accounts | Authentication |
| AUTH-002 | Password Status | Authentication |
| AUTH-003 | Sudo Privileges | Authentication |
| FILE-001 | World-Writable Files | File Security |
| FILE-002 | SUID Files | File Security |
| NET-003 | Network-Facing Ports | Network Security |
| SYS-002 | System Updates | System Security |
| PERSIST-001 | Root Cron Jobs | Persistence |
| AUTH-004 | Failed Authentication | Authentication |
| SYS-003 | System Errors | System Security |
| AUTH-005 | Password Aging | Authentication |
| FILE-003 | World-Writable Directories | File Security |

## Severity Levels

| Severity | Meaning |
|---|---|
| PASS | Security condition passed the check |
| INFO | Informational finding requiring awareness or review |
| WARN | Potential security weakness requiring attention |
| CRITICAL | High-risk security condition requiring immediate attention |

## Risk Scoring

The auditor calculates a simple heuristic risk score:

- INFO = 1 point
- WARN = 5 points
- CRITICAL = 10 points
- PASS = 0 points

Risk levels:

- LOW: below 25
- MEDIUM: 25–49
- HIGH: 50 or above

The risk score is a project-specific heuristic and is intended for security assessment practice, not as an industry-standard risk rating.

## Project Structure

```text
linux-security-auditor/
├── audit.sh
├── generate_report.py
├── sample_output.txt
├── README.md
└── .gitignore
```

## Requirements
Linux operating system
Bash
Python 3
sudo privileges for system-level checks

## Usage

Make the auditor executable:
chmod +x audit.sh

Run the auditor:
./audit.sh

Generate the JSON report:
python3 generate_report.py

The generated report will be saved as:
audit_report.json

## Example Result

Example audit summary:

===================================
          AUDIT SUMMARY
===================================
PASS     : 4
INFO     : 6
WARN     : 6
CRITICAL : 0

Risk Score : 36/100
Risk Level : MEDIUM

## Technologies Used
Bash
Python
Linux
Ubuntu
Linux command-line utilities
File permissions
Linux authentication and user management
Network inspection

## Learning Outcomes

This project provided practical experience with:
Linux security auditing
Bash scripting
Linux file permissions
User and privilege management
Authentication monitoring
Network exposure analysis
System hardening concepts
Security finding classification
Basic risk scoring
JSON report generation

## Disclaimer

This tool is intended for authorized security auditing, learning, and system administration purposes. Run it only on systems you own or have permission to assess.

