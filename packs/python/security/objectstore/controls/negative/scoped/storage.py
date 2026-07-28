
from minio import Minio


def get_client():
    """TLS on: not a transport finding."""
    return Minio("objects.example.com", access_key="k", secret_key="s", secure=True)


def ensure_bucket(c, bucket):
    """A grant scoped to the prefix that is genuinely public, read-only, is the FIX."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::media/vehicles/*"],
            }
        ],
    }
    c.set_bucket_policy(bucket, policy)


def private_bucket(c, bucket):
    """A policy with a named principal is not an anonymous grant."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/app"},
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": ["arn:aws:s3:::media/*"],
            }
        ],
    }
    c.set_bucket_policy(bucket, policy)
