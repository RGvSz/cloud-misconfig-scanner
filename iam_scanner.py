import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone

def check_root_access_keys(iam_client):
    findings = []
    try:
        summary = iam_client.get_account_summary()
        if summary['SummaryMap'].get('AccountAccessKeysPresent', 0) > 0:
            findings.append({
                'check': 'RootAccessKeys',
                'status': 'FAIL',
                'severity': 'CRITICAL',
                'detail': 'Root account has active access keys'
            })
    except ClientError as e:
        findings.append({'check': 'RootAccessKeys', 'status': 'ERROR', 'severity': 'LOW', 'detail': str(e)})
    return findings


def check_mfa_on_users(iam_client):
    findings = []
    try:
        users = iam_client.list_users()['Users']
        for user in users:
            mfa = iam_client.list_mfa_devices(UserName=user['UserName'])['MFADevices']
            if not mfa:
                findings.append({
                    'check': 'MFADisabled',
                    'status': 'FAIL',
                    'severity': 'HIGH',
                    'detail': f"User '{user['UserName']}' has no MFA enabled"
                })
    except ClientError as e:
        findings.append({'check': 'MFA', 'status': 'ERROR', 'severity': 'LOW', 'detail': str(e)})
    return findings


def check_old_access_keys(iam_client):
    findings = []
    try:
        users = iam_client.list_users()['Users']
        for user in users:
            keys = iam_client.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
            for key in keys:
                if key['Status'] == 'Active':
                    age = (datetime.now(timezone.utc) - key['CreateDate']).days
                    if age > 90:
                        findings.append({
                            'check': 'OldAccessKey',
                            'status': 'FAIL',
                            'severity': 'HIGH',
                            'detail': f"User '{user['UserName']}' has access key {age} days old"
                        })
    except ClientError as e:
        findings.append({'check': 'OldAccessKeys', 'status': 'ERROR', 'severity': 'LOW', 'detail': str(e)})
    return findings


def check_admin_users(iam_client):
    findings = []
    try:
        users = iam_client.list_users()['Users']
        for user in users:
            policies = iam_client.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
            for policy in policies:
                if 'AdministratorAccess' in policy['PolicyName']:
                    findings.append({
                        'check': 'AdminUser',
                        'status': 'FAIL',
                        'severity': 'CRITICAL',
                        'detail': f"User '{user['UserName']}' has AdministratorAccess policy"
                    })
    except ClientError as e:
        findings.append({'check': 'AdminUser', 'status': 'ERROR', 'severity': 'LOW', 'detail': str(e)})
    return findings


def scan_iam(session):
    iam = session.client('iam')
    print("\n[*] Starting IAM scan...\n")

    findings = []
    findings += check_root_access_keys(iam)
    findings += check_mfa_on_users(iam)
    findings += check_old_access_keys(iam)
    findings += check_admin_users(iam)

    if not findings:
        print("[+] No IAM misconfigurations found")
    for f in findings:
        print(f"  [{f['severity']}] {f['check']}: {f['detail']}")

    return findings


if __name__ == "__main__":
    session = boto3.Session()
    scan_iam(session)