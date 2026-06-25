import boto3
from botocore.exceptions import ClientError, NoCredentialsError

def test_connection():
    try:
        s3 = boto3.client('s3')
        response = s3.list_buckets()
        buckets = response['Buckets']
        print(f"[+] Connected to AWS successfully")
        print(f"[+] Found {len(buckets)} S3 buckets")
        for bucket in buckets:
            print(f"    -> {bucket['Name']}")
        return True
    except NoCredentialsError:
        print("[-] No AWS credentials found")
        return False
    except ClientError as e:
        print(f"[-] AWS Error: {e.response['Error']['Code']}")
        return False

if __name__ == "__main__":
    test_connection()