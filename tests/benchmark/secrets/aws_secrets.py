# BENCHMARK: secrets - aws_credentials
# WARNING: This file contains test/fake credentials for benchmark purposes only

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETKEY1"
AWS_DEFAULT_REGION = "us-east-1"


def get_s3_client():
    import boto3
    return boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_DEFAULT_REGION,
    )
