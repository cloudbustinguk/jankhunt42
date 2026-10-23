"""Nightly report export to object storage."""
import boto3

s3 = boto3.client("s3")


def publish(name: str, body: bytes) -> None:
    s3.put_object(Bucket="demo-reports-prod", Key=name, Body=body)
