import unittest
from unittest import TestCase
from datetime import datetime
import os

from .constants import DCAR_URL, S3_REPORT_BUCKET, JOB_ID, PROJECT_NAME, GITLAB_URL, LOCK_URL


class TestCommon(TestCase):
    def setUp(self):
        self._no_version_warning = "Version number must be set - example: '1.0' || Filename is incomplete without a version value"
        self.path = "this/is/a/test/path.txt"
        self.test_image_version = "1.1.0"

    def test_get_basename(self):
        from .common import get_basename

        assert get_basename(self.path) == "path.txt"
        assert get_basename(self.path) != self.path

    def test_get_publish_base_url(self):
        from .common import get_publish_base_url, get_datetime

        assert get_publish_base_url() == f"{DCAR_URL}/{S3_REPORT_BUCKET}/container-scan-reports/{PROJECT_NAME}/{get_datetime()}_{JOB_ID}"
        assert get_publish_base_url() != f"{DCAR_URL}/{S3_REPORT_BUCKET}/container-scan-reports/{PROJECT_NAME}/{get_datetime()}"

    def test_get_datetime(self):
        from .common import get_datetime
        from datetime import datetime

        test_date = get_datetime()
        test_date_object = datetime.strptime(test_date, '%Y-%m-%dT%H:%M:%S.%f')
        assert isinstance(test_date_object, datetime)

    def test_get_root_path(self):
        # This is being run currently as though the branch is master
        from .common import get_root_path
        from .constants import CURRENT_BRANCH

        assert get_root_path() == f"container-scan-reports/{PROJECT_NAME}"
        assert get_root_path() != f"testing/container-scan-reports/{PROJECT_NAME}"

    def test_get_base_bucket_directory(self):
        # Very similar to the above function, this is being run as though the branch is master
        from .common import get_base_bucket_directory

        assert get_base_bucket_directory() == "container-scan-reports"
        assert get_base_bucket_directory() != "testing/container-scan-reports"

    def test_is_production_branch(self):
        # Reading from env and the CI_COMMIT_BRANCH - currently is master
        from .common import is_production_branch

        if os.environ["CI_COMMIT_BRANCH"] == "master" or os.environ["CI_COMMIT_BRANCH"] == "development":
            assert is_production_branch() == True
        else:
            assert is_production_branch() == False

    def test_get_git_url(self):
        from .common import get_git_url

        assert os.environ["CI_SERVER_URL"] == get_git_url()

    def test_set_image_version(self):
        from .common import set_image_version, get_image_version

        set_image_version(self.test_image_version)
        assert get_image_version() == self.test_image_version

    def test_get_tar_filename(self):
        from .common import get_tar_filename, get_image_version, set_image_version

        set_image_version(self.test_image_version)
        assert get_tar_filename() == f"{PROJECT_NAME}-{get_image_version()}-reports-signature.tar.gz"

    def test_get_image_signature_filename(self):
        from .common import get_image_signature_filename, set_image_version, get_image_version

        set_image_version(self.test_image_version)
        assert get_image_signature_filename() == f"{PROJECT_NAME}-{get_image_version()}.sig"

    def test_get_image_filename(self):
        from .common import get_image_filename, set_image_version, get_image_version

        set_image_version(self.test_image_version)
        assert get_image_filename() == f"{PROJECT_NAME}-{get_image_version()}.tar"

    def test_get_image_version(self):
        from .common import get_image_version, set_image_version

        if not get_image_version():
            set_image_version(self.test_image_version)
        assert get_image_version() == self.test_image_version

    def test_get_lockname(self):
        from .common import get_lockname

        assert get_lockname() == LOCK_URL

    def test_get_simple_image_path(self):
        from .common import get_simple_image_path

        assert get_simple_image_path() == f"{PROJECT_NAME}/{PROJECT_NAME}"

    def test_get_tag(self):
        from .common import get_tag, set_image_version, get_image_version
        from .constants import CURRENT_BRANCH

        if not get_image_version():
            set_image_version(self.test_image_version)

        if CURRENT_BRANCH.lower() == "master":
            assert get_tag() == f"{get_image_version()}"
            assert get_tag() != f"{get_image_version()}-development"
            assert get_tag() != f"{get_image_version()}-testing"
        elif CURRENT_BRANCH.lower() == "development":
            assert get_tag() == f"{get_image_version()}-development"
            assert get_tag() != f"{get_image_version()}-testing"
            assert get_tag() != f"{get_image_version()}"
        else:
            assert get_tag() == f"{get_image_version()}-testing"
            assert get_tag() != f"{get_image_version()}-development"
            assert get_tag() != f"{get_image_version()}"

    def test_get_public_image_tag(self):
        from .common import get_public_image_tag, set_image_version, get_simple_image_path, get_tag

        set_image_version(self.test_image_version)
        assert get_public_image_tag() == f"{get_simple_image_path()}:{get_tag()}"

if __name__ == '__main__':
    unittest.main()