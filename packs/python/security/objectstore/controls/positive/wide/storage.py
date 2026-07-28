
from minio import Minio


def get_client():
    return Minio("minio:9000", access_key="k", secret_key="s", secure=False)


def ensure_bucket(c, bucket):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    c.set_bucket_policy(bucket, str(policy).replace("'", '"'))
