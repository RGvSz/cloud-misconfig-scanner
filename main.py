import boto3
import json
from datetime import datetime
from s3_scanner import scan_s3
from iam_scanner import scan_iam
from ec2_scanner import scan_ec2

def calculate_risk_score(all_findings):
    severity_weights = {
        'CRITICAL': 10,
        'HIGH': 7,
        'MEDIUM': 4,
        'LOW': 1
    }
    score = 0
    for finding in all_findings:
        score += severity_weights.get(finding.get('severity', 'LOW'), 0)
    return min(score, 100)

def generate_report(s3_findings, iam_findings, ec2_findings):
    flat_findings = []
    for bucket in s3_findings:
        flat_findings += bucket['findings']
    flat_findings += iam_findings
    flat_findings += ec2_findings

    score = calculate_risk_score(flat_findings)

    report = {
        'scan_time': datetime.utcnow().isoformat(),
        'risk_score': score,
        'total_findings': len(flat_findings),
        'summary': {
            'CRITICAL': sum(1 for f in flat_findings if f['severity'] == 'CRITICAL'),
            'HIGH':     sum(1 for f in flat_findings if f['severity'] == 'HIGH'),
            'MEDIUM':   sum(1 for f in flat_findings if f['severity'] == 'MEDIUM'),
            'LOW':      sum(1 for f in flat_findings if f['severity'] == 'LOW'),
        },
        's3': s3_findings,
        'iam': iam_findings,
        'ec2': ec2_findings
    }

    filename = f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(report, f, indent=4, default=str)

    return report, filename

def main():
    print("=" * 50)
    print("  Cloud Misconfiguration Scanner")
    print("=" * 50)

    session = boto3.Session()

    s3_findings  = scan_s3(session)
    iam_findings = scan_iam(session)
    ec2_findings = scan_ec2(session)

    report, filename = generate_report(s3_findings, iam_findings, ec2_findings)

    print("\n" + "=" * 50)
    print("  SCAN COMPLETE")
    print("=" * 50)
    print(f"  Risk Score   : {report['risk_score']}/100")
    print(f"  Total Findings: {report['total_findings']}")
    print(f"  CRITICAL     : {report['summary']['CRITICAL']}")
    print(f"  HIGH         : {report['summary']['HIGH']}")
    print(f"  MEDIUM       : {report['summary']['MEDIUM']}")
    print(f"  LOW          : {report['summary']['LOW']}")
    print(f"  Report saved : {filename}")
    print("=" * 50)

if __name__ == "__main__":
    main()