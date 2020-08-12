import os
from datetime import datetime

from .constants import *

global IMAGE_DATETIME
IMAGE_DATETIME = str(datetime.utcnow()).replace(' ', 'T')

_no_version_warning = "Version number must be set - example: '1.0' || Filename is incomplete without a version value"


def get_basename(path) -> str:
    """
    A simple function that will return the basename of a file/image given a specific path
    Return: String
    """
    return path.split('/')[-1]


def get_publish_base_url() -> str:
    """
    Function that returns the base URL for artifacts
    This was altered slightly from the Groovy implementation due to the JOB_ID GitLab CI variable which replaces the Jenkins BUILDNUMBER
    Return: String
    """
    return f"{DCAR_URL}/{S3_REPORT_BUCKET}/{get_root_path()}/{get_datetime()}_{JOB_ID}"


def get_datetime() -> str:
    """
    Function returns the global IMAGE_DATETIME so that all usage of the datetime will be of consistent value
    Return: String
    """
    return IMAGE_DATETIME


def get_root_path() -> str:
    """
    Function that returns the project-specific bucket path, whether that be testing or production
    Return: String
    """
    return f"{get_base_bucket_directory()}/{PROJECT_NAME}"


def get_base_bucket_directory() -> str:
    """
    Function that returns the bucket directory for a project, dependent on if it is a production branch (Master/Development) or not
    Return: String
    """
    try:
        path = "container-scan-reports"
        if is_production_branch(False):
            return path
        else:
            return f"testing/{path}"
    except Exception as e:
        print(e)


def is_production_branch(echo=True) -> bool:
    """
    Function that returns True/False if the branch is a production branch
    If the branch is Master/Development then it is a production branch
    Otherwise, returns False
    Args: echo - This bool will determine if the status is printed to the console or not, defaults to True
    Return: bool
    """
    # CI_COMMIT_REF_NAME
    # CI_COMMIT_BRANCH
    production = (CURRENT_BRANCH.lower() == "master") or (CURRENT_BRANCH.lower() == "development")
    if echo:
        print(f"is_production_branch: {CURRENT_BRANCH} - {'YES' if production else 'NO'}")
    return production


def get_git_url() -> str:
    """
    Function will return the constant GITLAB_URL unless it is not set
    Return: String
    """
    try:
        return GITLAB_URL
    except Exception as e:
        print(e)


def set_image_version(version: str):
    """
    Function will hold the value of the current image version and expose its value to all functions when needed
    This was necessary due to the Jenkins context no longer being necessary
    """
    global IMAGE_VERSION
    IMAGE_VERSION = version


def get_tar_filename() -> str:
    """
    Funciton that will return the filename for the tarball for the project
    NOTE: Function will raise a TypeError if there is no IMAGE_VERSION set
    Return: String
    """
    try:
        if IMAGE_VERSION is not None:
            return f"{PROJECT_NAME}-{IMAGE_VERSION}-reports-signature.tar.gz"
        else:
            raise TypeError(_no_version_warning)
    except Exception as e:
        print(e)


def get_image_signature_filename() -> str:
    """
    Function will return the signature file's filename
    NOTE: Function will raise a TypeError if there is no IMAGE_VERSION set
    Return: String
    """
    try:
        if IMAGE_VERSION is not None:
            return f"{PROJECT_NAME}-{IMAGE_VERSION}.sig"
        else:
            raise TypeError(_no_version_warning)
    except Exception as e:
        print(e)


def get_image_filename() -> str:
    """
    Function will return the filename of the tar that will be used by "docker load -i"
    NOTE: Function will raise a TypeError if there is no IMAGE_VERSION set
    Return: String
    """
    try:
        if IMAGE_VERSION is not None:
            return f"{PROJECT_NAME}-{IMAGE_VERSION}.tar"
        else:
            raise TypeError(_no_version_warning)
    except Exception as e:
        print(e)


def get_image_version() -> str:
    """
    Function that returns the image version number if it has been set
    NOTE: Function will raise a TypeError if there it no IMAGE_VERSION set
    Return: String
    """
    try:
        if IMAGE_VERSION is not None:
            return IMAGE_VERSION
        else:
            raise Exception("Version number must be set - example: '1.0'")
    except Exception as e:
        print(e)


def get_lockname() -> str:
    """
    Function will return the "lockname", which in the groovy implementation was set to the GIT_URL which is now the CI variable CI_REPOSITORY_URL
    NOTE: This CI variable is subject to be swapped upon confirmation of what the original GIT_URL was
    Return: String
    """
    return LOCK_URL


def get_simple_image_path() -> str:
    """
    Function will return the simple image path ex. sonarqube/sonarqube to hide details of the layout of the internal registry
    Return: String
    """
    return f"{PROJECT_NAME}/{PROJECT_NAME}"


def get_tag() -> str:
    """
    Get tag will return image tags like:
    master branch:              1.2.3
    development branch:         1.2.3-development
    contributor branches:       1.2.3-testing
    Return: String
    """
    if CURRENT_BRANCH.lower() == 'development':
        return f"{get_image_version()}-development"
    elif CURRENT_BRANCH.lower() == 'master':
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