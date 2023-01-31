#!/usr/bin/env python3

import os
import mimetypes
import boto3
from botocore.exceptions import ClientError
from ironbank.pipeline.utils import logger

log = logger.setup(name="s3upload")


def upload_file(file_name, bucket, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    access_key = os.environ["S3_ACCESS_KEY"]
    secret_key = os.environ["S3_SECRET_KEY"]

    filetype = mimetypes.guess_type(file_name)

    if not filetype[0]:
        # If mimetype is NoneType use default value
        mimetype = "application/octet-stream"
    elif filetype[1] == "gzip":
        # mimetypes returns 'application/x-tar'
        #   but for S3 to properly serve gzip we need to set to the following
        mimetype = "application/x-compressed-tar"
    else:
        mimetype = filetype[0]

    # TODO: Add signature
    extra_args = {
        "ContentType": mimetype,
        "ACL": "private",
    }

    log.debug("extra_args for %s: %s", file_name, extra_args)
    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name

    # Upload the file
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="us-gov-west-1",
    )
    try:
        s3_client.upload_file(file_name, bucket, object_name, extra_args)
    except ClientError:
        log.error("S3 client error occured")
        return False
    return True
