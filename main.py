import boto3
import json
from s3_scanner import scan_s3
from iam_scanner import scan_iam
from ec2_scanner import scan_ec2
from risk_scorer import run_scoring
from datetime import datetime, timezone
from report_generator import generate_html_report

def generate_report(s3_findings, iam_findings, ec2_findings, flat_findings, risk_score):
    report = {
        'scan_time': datetime.now(timezone.utc).isoformat(),
        'risk_score': risk_score,
        'total_findings': len(flat_findings),
        'summary': {
            'CRITICAL': sum(1 for f in flat_findings if f['severity'] == 'CRITICAL'),
            'HIGH':     sum(1 for f in flat_findings if f['severity'] == 'HIGH'),
            'MEDIUM':   sum(1 for f in flat_findings if f['severity'] == 'MEDIUM'),
            'LOW':      sum(1 for f in flat_findings if f['severity'] == 'LOW'),
        },
        'anomalies_detected': sum(1 for f in flat_findings if f.get('anomaly')),
        's3': s3_findings,
        'iam': iam_findings,
        'ec2': ec2_findings
    }

    filename = f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
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

    flat_findings, risk_score = run_scoring(s3_findings, iam_findings, ec2_findings)

    report, filename = generate_report(s3_findings, iam_findings, ec2_findings, flat_findings, risk_score)
    html_file = generate_html_report(s3_findings, iam_findings, ec2_findings, flat_findings, risk_score)
    print(f"  HTML Report     : {html_file}")
    print("\n" + "=" * 50)
    print("  SCAN COMPLETE")
    print("=" * 50)
    print(f"  Risk Score      : {report['risk_score']}/100")
    print(f"  Total Findings  : {report['total_findings']}")
    print(f"  CRITICAL        : {report['summary']['CRITICAL']}")
    print(f"  HIGH            : {report['summary']['HIGH']}")
    print(f"  MEDIUM          : {report['summary']['MEDIUM']}")
    print(f"  LOW             : {report['summary']['LOW']}")
    print(f"  Anomalies       : {report['anomalies_detected']}")
    print(f"  Report saved    : {filename}")
    print("=" * 50)

if __name__ == "__main__":
    main()