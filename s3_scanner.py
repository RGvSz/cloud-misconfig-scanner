import boto3
from botocore.exceptions import ClientError

def check_bucket_public_access(s3_client, bucket_name):
    findings = []
    
    # Check block public access settings
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response['PublicAccessBlockConfiguration']
        
        if not config.get('BlockPublicAcls', False):
            findings.append({
                'check': 'BlockPublicAcls',
                'status': 'FAIL',
                'severity': 'CRITICAL',
                'detail': 'Bucket allows public ACLs'
            })
        if not config.get('BlockPublicPolicy', False):
            findings.append({
                'check': 'BlockPublicPolicy',
                'status': 'FAIL',
                'severity': 'CRITICAL',
                'detail': 'Bucket allows public bucket policies'
            })
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            findings.append({
                'check': 'PublicAccessBlock',
                'status': 'FAIL',
                'severity': 'CRITICAL',
                'detail': 'No public access block configuration found'
            })

    return findings


def check_bucket_versioning(s3_client, bucket_name):
    findings = []
    try:
        response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        status = response.get('Status', 'Disabled')
        if status != 'Enabled':
            findings.append({
                'check': 'Versioning',
                'status': 'FAIL',
                'severity': 'MEDIUM',
                'detail': f'Versioning is {status}'
            })
    except ClientError as e:
        findings.append({
            'check': 'Versioning',
            'status': 'ERROR',
            'severity': 'LOW',
            'detail': str(e)
        })
    return findings


def check_bucket_encryption(s3_client, bucket_name):
    findings = []
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            findings.append({
                'check': 'Encryption',
                'status': 'FAIL',
                'severity': 'HIGH',
                'detail': 'Bucket has no default encryption'
            })
    return findings


def scan_s3(session):
    s3 = session.client('s3')
    print("\n[*] Starting S3 scan...\n")
    
    buckets = s3.list_buckets().get('Buckets', [])
    
    if not buckets:
        print("[-] No S3 buckets found")
        return []
    
    all_findings = []
    
    for bucket in buckets:
        name = bucket['Name']
        print(f"[*] Scanning bucket: {name}")
        
        findings = []
        findings += check_bucket_public_access(s3, name)
        findings += check_bucket_versioning(s3, name)
        findings += check_bucket_encryption(s3, name)
        
        for f in findings:
            print(f"  [{f['severity']}] {f['check']}: {f['detail']}")
        
        all_findings.append({'bucket': name, 'findings': findings})
    
    return all_findings


if __name__ == "__main__":
    session = boto3.Session()
    scan_s3(session)