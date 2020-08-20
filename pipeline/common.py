import os
import requests
import urllib3
import json
import urllib.parse as url_helper
from datetime import datetime
from typing import List
import boto3
import botocore
import re

from .constants import CURRENT_BRANCH, GITLAB_URL, S3_REPORT_BUCKET, JOB_ID, PROJECT_NAME, LOCK_URL, DCAR_URL

# GLOBALS
global _IMAGE_DATETIME
_IMAGE_DATETIME = datetime.utcnow().isoformat()
global _CURRENT_BRANCH
_CURRENT_BRANCH = CURRENT_BRANCH
global _GITLAB_URL
_GITLAB_URL = GITLAB_URL
global _S3_REPORT_BUCKET
_S3_REPORT_BUCKET = S3_REPORT_BUCKET
global _JOB_ID
_JOB_ID = JOB_ID
global _PROJECT_NAME
_PROJECT_NAME = PROJECT_NAME
global _LOCK_URL
_LOCK_URL = LOCK_URL
global _DCAR_URL
_DCAR_URL = DCAR_URL

_no_version_warning = "Version number must be set - example: '1.0' || Filename is incomplete without a version value"

_client = boto3.client('s3')


def get_basename(path: str) -> str:
    """
    A simple function that will return the basename of a file/image given a specific path
    Return: String
    """
    assert isinstance(path, str)
    return path.split('/')[-1]


def get_publish_base_url() -> str:
    """
    Function that returns the base URL for artifacts
    This was altered slightly from the Groovy implementation due to the JOB_ID GitLab CI variable which replaces the Jenkins BUILDNUMBER
    Return: String
    """
    return f"{_DCAR_URL}/{_S3_REPORT_BUCKET}/{get_root_path()}/{get_datetime()}_{_JOB_ID}"


def get_datetime() -> str:
    """
    Function returns the global IMAGE_DATETIME so that all usage of the datetime will be of consistent value
    Return: String
    """
    return _IMAGE_DATETIME


def get_root_path() -> str:
    """
    Function that returns the project-specific bucket path, whether that be testing or production
    Return: String
    """
    return f"{get_base_bucket_directory()}/{_PROJECT_NAME}"


def get_base_bucket_directory() -> str:
    """
    Function that returns the bucket directory for a project, dependent on if it is a production branch (Master/Development) or not
    Return: String
    """
    path = "container-scan-reports"
    if is_production_branch(False):
        return path
    else:
        return f"testing/{path}"


def is_production_branch(echo: bool=True) -> bool:
    """
    Function that returns True/False if the branch is a production branch
    If the branch is Master/Development then it is a production branch
    Otherwise, returns False
    Args: echo - This bool will determine if the status is printed to the console or not, defaults to True
    Return: bool
    """
    # CI_COMMIT_REF_NAME
    # CI_COMMIT_BRANCH
    production = (_CURRENT_BRANCH.lower() == "master") or (_CURRENT_BRANCH.lower() == "development")
    if echo:
        print(f"is_production_branch: {_CURRENT_BRANCH} - {'YES' if production else 'NO'}")
    return production


def get_git_url() -> str:
    """
    Function will return the constant GITLAB_URL unless it is not set
    Return: String
    """
    return _GITLAB_URL


def set_image_version(image_version: str):
    """
    Function will hold the value of the current image version and expose its value to all functions when needed
    This was necessary due to the Jenkins context no longer being necessary
    """
    global _IMAGE_VERSION
    _IMAGE_VERSION = image_version


def get_tar_filename() -> str:
    """
    Funciton that will return the filename for the tarball for the project
    NOTE: Function will raise a NameError if there is no IMAGE_VERSION set
    Return: String
    """
    if get_image_version() is not None:
        return f"{_PROJECT_NAME}-{get_image_version()}-reports-signature.tar.gz"
    else:
        raise NameError(_no_version_warning)


def get_image_signature_filename() -> str:
    """
    Function will return the signature file's filename
    NOTE: Function will raise a NameError if there is no IMAGE_VERSION set
    Return: String
    """
    if get_image_version() is not None:
        return f"{_PROJECT_NAME}-{get_image_version()}.sig"
    else:
        raise NameError(_no_version_warning)


def get_image_filename() -> str:
    """
    Function will return the filename of the tar that will be used by "docker load -i"
    NOTE: Function will raise a NameError if there is no IMAGE_VERSION set
    Return: String
    """
    if get_image_version() is not None:
        return f"{_PROJECT_NAME}-{get_image_version()}.tar"
    else:
        raise NameError(_no_version_warning)


def get_image_version() -> str:
    """
    Function that returns the image version number if it has been set
    NOTE: Function will raise a NameError if there it no IMAGE_VERSION set
    Return: String
    """
    if _IMAGE_VERSION is not None:
        return _IMAGE_VERSION
    else:
        raise NameError(_no_version_warning)


def get_lockname() -> str:
    """
    Function will return the "lockname", which in the groovy implementation was set to the GIT_URL which is now the CI variable CI_REPOSITORY_URL
    NOTE: This CI variable is subject to be swapped upon confirmation of what the original GIT_URL was
    Return: String
    """
    return _LOCK_URL


def get_simple_image_path() -> str:
    """
    Function will return the simple image path ex. sonarqube/sonarqube to hide details of the layout of the internal registry
    Return: String
    """
    return f"{_PROJECT_NAME}/{_PROJECT_NAME}"


def get_tag() -> str:
    """
    Get tag will return image tags like:
    master branch:              1.2.3
    development branch:         1.2.3-development
    contributor branches:       1.2.3-testing
    Return: String
    """
    if _CURRENT_BRANCH.lower() == 'development':
        return f"{get_image_version()}-development"
    elif _CURRENT_BRANCH.lower() == 'master':
        return f"{get_image_version()}"
    else:
        # All other Contributor branches
        return f"{get_image_version()}-testing"


def get_public_image_tag() -> str:
    """
    Image path and tag for the internal registry details are removed.
    This is for tagging images before they are exported to a file so we
    don't export the internal registy service address with the image.
    Return: String
    """
    return f"{get_simple_image_path()}:{get_tag()}"


def path_join(main_path: str, appendage: str) -> str:
    """
    Groovy implementation overcomplicated this - simply using urllib.parse to join two paths
    Args:
         main_path: str :: This is the body of the path that will be added to
         appendage: str :: The end of the new path, ala a filename
    Return: String
    """
    # Undecided if it should join two paths or just a list of strings - for now, going the two paths route
    return url_helper.urljoin(main_path, appendage)


def validate_s3_bucket_endpoints(json: dict, bucket_name: str) -> List:
    """
    Function will check to see if endpoints contained in the JSON data exist in the supplied bucket
    Args:
        json: dict :: This is the data, for example latest.json, that contains S3 endpoints for validating
        bucket_name: str :: The name of the bucket in which to search for the endpoints
    Return: List
    """
    # check to see if the bucket exists
    bad_paths = []
    try:
        bucket_exists = _client.head_bucket(Bucket=f"{bucket_name}")
        if bucket_exists:
            json_data = json.loads(json)
            for key in json_data:
                if json_data[key].startswith('https://'):
                    path = re.sub(r'^https:\/\/.*\/ironbank-pipeline-artifacts\/', '', path)
                    if not _s3_object_exists(path):
                        print(f"Error validating {S3_REPORT_BUCKET} S3 element {key} at the following path: {path}")
                        bad_paths.append({str(key): str(path)})
            if len(bad_paths) > 0:
                print("Either elements do not exist in the S3 or the documented path is wrong")
                print(*bad_paths, sep="\n")
                return bad_paths
            # Will return an empty list if no bad paths are found
            else:
                return bad_paths

    except botocore.exceptions.ClientError as e:
        print(f"There has been an error with locating the bucket: {bucket_name} - {e}")


def _s3_object_exists(path: str) -> bool:
    """
    This helper function will check to see if the path exists in the bucket
    Args:
        path: str :: The path being validated in the bucket
    Return: Bool
    """
    s3 = boto3.resource('s3')
    bucket = s3.bucket(S3_REPORT_BUCKET)
    bucket_objects = list(bucket.objects.filter(prefix=path))
    if len(bucket_objects) > 0 and bucket_objects[0].key == path:
        return True
    else:
        return False

def validate_aws_region(region: str) -> bool:
    """
    Use regular expression to ensure AWS region is a valid string
    :param region: region from resource
    :return: Bool (true if valid, false if not)
    """
    r = re.compile(r'(us(-gov)?|ap|ca|cn|eu|me|sa)-(north|south|east|west|central){1,2}-[1-9]')
    return bool(r.search(region))
