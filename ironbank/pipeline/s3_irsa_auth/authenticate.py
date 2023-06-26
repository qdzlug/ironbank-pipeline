import boto3
from pathlib import Path
import os
from ironbank.pipeline.utils import logger

log = logger.setup("s3_irsa_authenticator")


def authenticate(region):
    # authenticate the session client
    sts_client = boto3.client("sts")
    web_token = None
    try:
        web_token = Path(os.environ["AWS_WEB_IDENTITY_TOKEN_FILE"]).read_text()
        role_arn = os.environ["AWS_ROLE_ARN"]
    except KeyError as ke:
        log.error("Error while accessing environment variable")
        log.error(ke)
        raise ke
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
            region=region,
        )
        return session.client("s3")
    except Exception as e:
        log.error("An Error Occured While Authenticating The S3 Client")
        log.error(e)
        raise
