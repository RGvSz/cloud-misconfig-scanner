import boto3
from botocore.exceptions import ClientError

DANGEROUS_PORTS = {
    22: 'SSH',
    3389: 'RDP',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    27017: 'MongoDB',
    6379: 'Redis'
}

def check_security_groups(ec2_client, region):
    findings = []
    try:
        sgs = ec2_client.describe_security_groups()['SecurityGroups']
        for sg in sgs:
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 65535)
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        for port, service in DANGEROUS_PORTS.items():
                            if from_port <= port <= to_port:
                                findings.append({
                                    'check': 'OpenDangerousPort',
                                    'status': 'FAIL',
                                    'severity': 'CRITICAL',
                                    'detail': f"SG '{sg['GroupName']}' in {region}: {service} port {port} open to internet"
                                })
    except ClientError as e:
        findings.append({'check': 'SecurityGroups', 'status': 'ERROR', 'severity': 'LOW', 'detail': str(e)})
    return findings


def scan_ec2(session):
    regions = ['ap-south-1', 'us-east-1', 'us-west-2', 'eu-west-1']
    print("\n[*] Starting EC2 scan...\n")

    all_findings = []
    for region in regions:
        print(f"[*] Scanning region: {region}")
        ec2 = session.client('ec2', region_name=region)
        findings = check_security_groups(ec2, region)
        if not findings:
            print(f"  [+] No misconfigurations found in {region}")
        for f in findings:
            print(f"  [{f['severity']}] {f['check']}: {f['detail']}")
        all_findings += findings

    return all_findings


if __name__ == "__main__":
    session = boto3.Session()
    scan_ec2(session)