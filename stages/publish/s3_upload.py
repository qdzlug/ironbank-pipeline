import logging
import boto3
import os
import argparse
import datetime
from botocore.exceptions import ClientError
#from botocore.config import Config


def upload_file(file_name, bucket, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """
    
    access_key = os.environ["S3_ACCESS_KEY"]
    secret_key = os.environ["S3_SECRET_KEY"]

#    pipeline_artifacts_config = Config(region_name='us-gov-west-1')

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name

    # Upload the file
    s3_client = boto3.client('s3',
                             aws_access_key_id=access_key,
                             aws_secret_access_key=secret_key,
                             region_name='us-gov-west-1'
                      )
    try:
        response = s3_client.upload_file(file_name, bucket, object_name, 
                                         ExtraArgs={
						    'ACL': 'x-amz-acl:private',  
                                                    'ContentType': 'application/octet-stream'
                                                   }
                                        )
    except ClientError as e:
        logging.error(e)
        return False
    return True

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description = 'Uploading various reports and files to DCCSCR S3')

    parser.add_argument('--filename',   help='File to upload')
    parser.add_argument('--bucket',  help='Bucket to upload to')
    parser.add_argument('--dest',   help='S3 object path')
    args = parser.parse_args()

    file_name = args.filename
    bucket = args.bucket
    object_name = args.dest

    upload_file(file_name, bucket, object_name)
