# Cloud Misconfiguration Scanner

Automated AWS security scanner that detects misconfigurations across S3, IAM, and EC2 services.

## Features

- **S3 Scanner** — Detects public buckets, missing encryption, disabled versioning
- **IAM Scanner** — Detects missing MFA, old access keys, admin privilege abuse, root key exposure
- **EC2 Scanner** — Detects dangerous ports open to internet across multiple regions
- **Risk Scoring** — Weighted severity scoring (CRITICAL/HIGH/MEDIUM/LOW)
- **JSON Reports** — Machine-readable output for SIEM integration

## Tech Stack

- Python 3.x
- boto3 (AWS SDK)
- AWS Free Tier (S3, IAM, EC2)

## Setup

```bash
pip install boto3
aws configure
python main.py
```

## Sample Output

Risk Score   : 31/100

Total Findings: 4

CRITICAL     : 2

HIGH         : 1

MEDIUM       : 1

## Checks Performed

| Service | Check | Severity |
|---------|-------|----------|
| S3 | Block public access disabled | CRITICAL |
| S3 | Versioning disabled | MEDIUM |
| S3 | Encryption missing | HIGH |
| IAM | MFA not enabled | HIGH |
| IAM | Root account access keys | CRITICAL |
| IAM | Access keys older than 90 days | HIGH |
| IAM | AdministratorAccess on user | CRITICAL |
| EC2 | SSH open to 0.0.0.0/0 | CRITICAL |
| EC2 | RDP open to 0.0.0.0/0 | CRITICAL |
| EC2 | Database ports exposed | CRITICAL |

## Relevance

Built as part of cloud security assessment practice — mirrors functionality of commercial tools like ScoutSuite and Prowler.