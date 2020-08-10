import os
from datetime import datetime

from .constants import *

global IMAGE_DATETIME
IMAGE_DATETIME = str(datetime.utcnow()).replace(' ', 'T')

_no_version_warning = "Version number must be set - example: '1.0' || Filename is incomplete without a version value"


def get_publish_base_url():
    # PREVIOUSLY remoteReportDirectory equalled datetime_BUILDNUMBER
    return f"{DCAR_URL}/{S3_REPORT_BUCKET}/{get_root_path()}/{get_datetime()}_{JOB_ID}"


# Made this a function because there were multiple places where the datetime was used
# in the replaced groovy code, so this way the timestamp is consistent for each job
def get_datetime():
    return IMAGE_DATETIME


def get_root_path():
    return f"{get_base_bucket_directory()}/{PROJECT_NAME}"


def get_base_bucket_directory():
    try:
        path = "container-scan-reports"
        if is_production_branch(False):
            return path
        else:
            return f"testing/{path}"
    except Exception as e:
        print(e)


def is_production_branch(echo=True):
    # CI_COMMIT_REF_NAME
    # CI_COMMIT_BRANCH
    production = (CURRENT_BRANCH.lower() == "master") or (CURRENT_BRANCH.lower() == "development")
    if echo:
        print(f"is_production_branch: {CURRENT_BRANCH} {'YES' if production else 'NO'}")
    return production


def get_basename(path):
    return path.split('/')[-1]


def get_git_url():
    try:
        return GITLAB_URL
    except Exception as e:
        print(e)


def set_image_version(version):
    global IMAGE_VERSION
    IMAGE_VERSION = version


def get_tar_filename():
    try:
        if IMAGE_VERSION is not None:
            return f"{PROJECT_NAME}-{IMAGE_VERSION}-reports-signature.tar.gz"
        else:
            raise TypeError(_no_version_warning)
    except Exception as e:
        print(e)


def get_image_signature_filename():
    try:
        if IMAGE_VERSION is not None:
            return f"{PROJECT_NAME}-{IMAGE_VERSION}.sig"
        else:
            raise TypeError(_no_version_warning)
    except Exception as e:
        print(e)


def get_image_filename():
    try:
        if IMAGE_VERSION is not None:
            return f"{PROJECT_NAME}-{IMAGE_VERSION}.tar"
        else:
            raise TypeError(_no_version_warning)
    except Exception as e:
        print(e)


def get_version():
    try:
        if IMAGE_VERSION is not None:
            return IMAGE_VERSION
        else:
            raise Exception("Version number must be set - example: '1.0'")
    except Exception as e:
        print(e)


def get_lockname():
    # returned the lockname if it was set, which was set to the GIT_URL
    return GITLAB_URL


def get_simple_image_path():
    return f"{PROJECT_NAME}/{PROJECT_NAME}"


def get_tag():
    """
    Get tag will return image tags like:
    master branch:              1.2.3
    development branch:         1.2.3-development
    contributor branches:       1.2.3-testing
    """
    if CURRENT_BRANCH.lower() == 'development':
        return f"{get_version()}-development"
    elif CURRENT_BRANCH.lower() == 'master':
        return f"{get_version()}"
    else:
        # All other Contributor branches
        return f"{get_version()}-testing"


def get_public_image_tag():
    """
    Image path and tag for the internal registry details are removed.
    This is for tagging images before they are exported to a file so we
    don't export the internal registy service address with the image.
    """
    return f"{get_simple_image_path()}:{get_tag()}"