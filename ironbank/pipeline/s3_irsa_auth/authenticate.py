import boto3
from pathlib import Path
import os
from ironbank.pipeline.utils import logger

log = logger.setup("s3_irsa_authenticator")


def authenticate_client(region):
    """Authenticates and returns an AWS S3 client for a specific region.

    This function uses AWS Security Token Service (STS) to assume a role with
    web identity and create an authenticated session. It then returns an S3
    client using the credentials from this session.

    The web identity token and role ARN are read from environment variables
    "AWS_WEB_IDENTITY_TOKEN_FILE" and "AWS_ROLE_ARN" respectively.

    In case of any error during authentication, the exception is logged and re-raised.

    Args:
        region (str): The AWS region to authenticate the S3 client for.

    Returns:
        botocore.client.S3: An instance of an S3 client authenticated for the
        specified region.

    Raises:
        KeyError: If the necessary environment variables are not set.
        botocore.exceptions.BotoCoreError: If there is a problem in creating the
        session or client, or in assuming the role with web identity.
    """
    sts_client = boto3.client("sts")
    web_token = None
    try:
        web_token = Path(os.environ["AWS_WEB_IDENTITY_TOKEN_FILE"]).read_text(
            encoding="utf-8"
        )
        role_arn = os.environ["AWS_ROLE_ARN"]
    except KeyError as key_error:
        log.error("Error while accessing environment variable")
        log.error(key_error)
        raise key_error
    try:
        assumed_role_object = sts_client.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName="irsa_session",
            WebIdentityToken=web_token,
        )
        session = boto3.Session(
            aws_access_key_id=assumed_role_object["Credentials"]["AccessKeyId"],
            aws_secret_access_key=assumed_role_object["Credentials"]["SecretAccessKey"],
            aws_session_token=assumed_role_object["Credentials"]["SessionToken"],
            region_name=region,
        )
        return session.client("s3")
    except Exception as e:
        log.error("An Error Occured While Authenticating The S3 Client")
        log.error(e)
        raise
