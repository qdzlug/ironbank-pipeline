import unittest
from unittest import TestCase
from unittest import mock
from datetime import datetime
import os
from . import common

class TestCommon(TestCase):
    def setUp(self):
        from .constants import DCAR_URL, S3_REPORT_BUCKET, JOB_ID, PROJECT_NAME, GITLAB_URL, LOCK_URL, CURRENT_BRANCH
        self._no_version_warning = "Version number must be set - example: '1.0' || Filename is incomplete without a version value"
        self.path = "this/is/a/test/path.txt"
        self.test_image_version = "1.1.0"
        self.dcar_url = DCAR_URL
        self.s3_report_bucket = S3_REPORT_BUCKET
        self.job_id = JOB_ID
        self.project_name = PROJECT_NAME
        self.gitlab_url = GITLAB_URL
        self.lock_url = LOCK_URL
        self.current_branch = CURRENT_BRANCH

    def test_get_basename(self):
        from .common import get_basename

        assert get_basename(self.path) == "path.txt"
        assert get_basename(self.path) != self.path

    def test_get_publish_base_url(self):
        from .common import get_publish_base_url, get_datetime

        assert get_publish_base_url() == f"{self.dcar_url}/{self.s3_report_bucket}/container-scan-reports/{self.project_name}/{get_datetime()}_{self.job_id}"
        assert get_publish_base_url() != f"{self.dcar_url}/{self.s3_report_bucket}/container-scan-reports/{self.project_name}/{get_datetime()}"

    def test_get_datetime(self):
        from .common import get_datetime
        from datetime import datetime

        test_date = get_datetime()
        test_date_object = datetime.strptime(test_date, '%Y-%m-%dT%H:%M:%S.%f')
        assert isinstance(test_date_object, datetime)

    def test_get_root_path(self):
        # This is being run currently as though the branch is master
        from .common import get_root_path

        assert get_root_path() == f"container-scan-reports/{self.project_name}"
        assert get_root_path() != f"testing/container-scan-reports/{self.project_name}"

    def test_get_base_bucket_directory(self):
        # Very similar to the above function, this is being run as though the branch is master
        from .common import get_base_bucket_directory

        assert get_base_bucket_directory() == "container-scan-reports"
        assert get_base_bucket_directory() != "testing/container-scan-reports"

    @mock.patch.object(common, 'get_base_bucket_directory', mock.Mock(return_value="testing/container-scan-reports"))
    def test_get_base_bucket_directory_feature(self):
        from . import common
        assert common.get_base_bucket_directory() == "testing/container-scan-reports"
        assert common.get_base_bucket_directory() != "container-scan-reports"

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
        assert get_tar_filename() == f"{self.project_name}-{get_image_version()}-reports-signature.tar.gz"

        set_image_version(None)
        TestCase.assertRaises(NameError, NameError)
        set_image_version(self.test_image_version)

    def test_get_image_signature_filename(self):
        from .common import get_image_signature_filename, set_image_version, get_image_version

        set_image_version(self.test_image_version)
        assert get_image_signature_filename() == f"{self.project_name}-{get_image_version()}.sig"

        set_image_version(None)
        TestCase.assertRaises(NameError, NameError)
        set_image_version(self.test_image_version)

    def test_get_image_filename(self):
        from .common import get_image_filename, set_image_version, get_image_version

        set_image_version(self.test_image_version)
        assert get_image_filename() == f"{self.project_name}-{get_image_version()}.tar"

        set_image_version(None)
        TestCase.assertRaises(NameError, NameError)
        set_image_version(self.test_image_version)

    def test_get_image_version(self):
        from .common import get_image_version, set_image_version

        if not get_image_version():
            set_image_version(self.test_image_version)
        assert get_image_version() == self.test_image_version

        set_image_version(None)
        TestCase.assertRaises(NameError, NameError)
        set_image_version(self.test_image_version)

    def test_get_lockname(self):
        from .common import get_lockname

        assert get_lockname() == self.lock_url

    def test_get_simple_image_path(self):
        from .common import get_simple_image_path

        assert get_simple_image_path() == f"{self.project_name}/{self.project_name}"

    def test_get_tag_master(self):
        from .common import get_tag, set_image_version, get_image_version

        set_image_version(self.test_image_version)

        assert get_tag() == f"{get_image_version()}"
        assert get_tag() != f"{get_image_version()}-development"
        assert get_tag() != f"{get_image_version()}-testing"

    @mock.patch.object(common, 'get_tag', mock.Mock(return_value="1.1.0-development"))
    def test_get_tag_development(self):

        common.set_image_version(self.test_image_version)

        assert common.get_tag() == f"{common.get_image_version()}-development"
        assert common.get_tag() != f"{common.get_image_version()}-testing"
        assert common.get_tag() != f"{common.get_image_version()}"

    @mock.patch.object(common, 'get_tag', mock.Mock(return_value="1.1.0-testing"))
    def test_get_tag_feature_branch(self):
        common.set_image_version(self.test_image_version)

        assert common.get_tag() == f"{common.get_image_version()}-testing"
        assert common.get_tag() != f"{common.get_image_version()}-development"
        assert common.get_tag() != f"{common.get_image_version()}"

    def test_get_public_image_tag(self):
        from .common import get_public_image_tag, set_image_version, get_simple_image_path, get_tag

        set_image_version(self.test_image_version)
        assert get_public_image_tag() == f"{get_simple_image_path()}:{get_tag()}"

if __name__ == '__main__':
    unittest.main()