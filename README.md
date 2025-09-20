Cloud & On-Premise Misconfiguration Scanner (Demo)
Overview

This project is a demo security scanner that simulates the detection of common misconfigurations in both cloud environments (AWS) and on-premise systems (Linux servers).

It generates detailed JSON and text-based reports highlighting issues such as:

Publicly accessible S3 buckets (AWS)

Weak IAM roles and permissions (AWS)

Insecure SSH configurations (on-prem)

Other high-level misconfigurations

The tool is designed to provide practical experience in identifying risks, documenting findings, and suggesting remediations — skills highly relevant in cybersecurity, cloud security, and compliance roles.

Features

Simulated AWS misconfiguration checks (S3, IAM)

On-prem security checks (SSH config, firewall rules)

Generates both JSON and TXT reports

Demo-friendly (no real AWS credentials required)

Modular design for easy extension

Tech Stack

Python 3.x

argparse (command-line interface)

json and file handling (report generation)

Modular, extensible structure

Project Structure
├── scanner.py              # Main entry point
├── cloud_scanner.py        # Simulated AWS misconfig checks
├── onprem_scanner.py       # Simulated on-prem checks
├── utils.py                # Helpers for reports
├── sample_report.txt       # Example text output
├── sample_output.json      # Example JSON output
└── README.md               # Documentation

Installation

Clone the repo:

git clone https://github.com/your-username/cloud_onprem_misconfig_demo.git
cd cloud_onprem_misconfig_demo


(Optional) Create a virtual environment:

python3 -m venv venv
source venv/bin/activate   # macOS/Linux
venv\Scripts\activate      # Windows


Run the tool in demo mode:

python scanner.py --demo --aws --onprem

Sample Output
Console Output
[INFO] Running in DEMO mode
[✓] Checking AWS S3 Buckets...
    - bucket 'public-data-bucket' is publicly accessible! (High Risk)
[✓] Checking IAM Roles...
    - role 'adminRole' has excessive permissions! (Medium Risk)
[✓] Checking SSH Config...
    - PasswordAuthentication is enabled (Medium Risk)
[✓] Checking Firewall...
    - Port 22 open to 0.0.0.0/0 (High Risk)

Scan complete! Reports saved to:
  -> sample_report.txt
  -> sample_output.json

JSON Report (excerpt)
{
  "cloud": {
    "s3_buckets": [
      {"name": "public-data-bucket", "issue": "public access", "risk": "high"}
    ],
    "iam_roles": [
      {"name": "adminRole", "issue": "excessive permissions", "risk": "medium"}
    ]
  },
  "onprem": {
    "ssh": {"PasswordAuthentication": "enabled", "risk": "medium"},
    "firewall": {"port_22": "open to all", "risk": "high"}
  }
}
