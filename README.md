# Cloud Misconfiguration Scanner

Automated AWS security scanner that detects misconfigurations across S3, IAM, 
and EC2 services — with ML-based anomaly detection and visual HTML reporting.

## Features

- **S3 Scanner** — Detects public buckets, missing encryption, disabled versioning
- **IAM Scanner** — Detects missing MFA, old access keys, admin privilege abuse, root key exposure
- **EC2 Scanner** — Detects dangerous ports open to internet across multiple regions
- **ML Risk Scoring** — IsolationForest anomaly detection on findings
- **HTML Report** — Visual dark-theme report with severity breakdown
- **JSON Report** — Machine-readable output for SIEM integration

## Tech Stack

- Python 3.x
- boto3 (AWS SDK)
- scikit-learn (IsolationForest)
- numpy
- AWS Free Tier (S3, IAM, EC2)

## Setup

```bash
pip install boto3 scikit-learn numpy
aws configure
python main.py
```

## Sample Output
Risk Score      : 31/100

Total Findings  : 4

CRITICAL        : 2

HIGH            : 1

MEDIUM          : 1

LOW             : 0

Anomalies       : 1

## Checks Performed

| Service | Check | Severity |
|---------|-------|----------|
| S3 | Block public access disabled | CRITICAL |
| S3 | Versioning disabled | MEDIUM |
| S3 | Encryption missing | HIGH |
| IAM | MFA not enabled | HIGH |
| IAM | Root account access keys active | CRITICAL |
| IAM | Access keys older than 90 days | HIGH |
| IAM | AdministratorAccess on user | CRITICAL |
| EC2 | SSH open to 0.0.0.0/0 | CRITICAL |
| EC2 | RDP open to 0.0.0.0/0 | CRITICAL |
| EC2 | Database ports exposed to internet | CRITICAL |

## Project Structure
├── main.py              # Orchestrates full scan

├── s3_scanner.py        # S3 misconfiguration checks

├── iam_scanner.py       # IAM misconfiguration checks

├── ec2_scanner.py       # EC2 security group checks

├── risk_scorer.py       # ML anomaly detection + scoring

├── report_generator.py  # HTML report generation

## Relevance

Built as part of an offensive security portfolio targeting cloud assessment 
skills. Mirrors core functionality of commercial tools like ScoutSuite and 
Prowler — built from scratch using boto3 and sklearn.
