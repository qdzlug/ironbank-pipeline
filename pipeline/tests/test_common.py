import os
import unittest
from unittest import TestCase
from unittest import mock
from datetime import datetime

# Set up the Environment Variables
# We must initialize them before importing anything from pipeline,
#    as the constants will be read from os.environ on import
os.environ["CI_SERVER_URL"] = "https://repo1.dsop.io"
os.environ["CI_JOB_ID"] = "999"
os.environ["CI_PROJECT_NAME"] = "test_project"
os.environ["CI_COMMIT_BRANCH"] = "master"
os.environ["CI_PROJECT_URL"] = "https://repo1.dsop.io/test/test_project"
os.environ["CI_REPOSITORY_URL"] = "https://registry1.dsop.io/test/test_project"
from pipeline import common
from pipeline import constants

class TestCommon(TestCase):
    def setUp(self):
        from pipeline.constants import DCAR_URL, S3_REPORT_BUCKET, JOB_ID, PROJECT_NAME, GITLAB_URL, LOCK_URL, CURRENT_BRANCH
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
        from pipeline.common import get_basename

        # Confirm correct value
        self.assertEqual(get_basename(self.path), "path.txt")

        # Assert Failures for invalid types
        for invalid_type in [True, 5, 1.2, b'bytestring']:
            with self.assertRaises(AssertionError):
                get_basename(invalid_type)


    def test_get_publish_base_url(self):
        from pipeline.common import get_publish_base_url, get_datetime

        self.assertEqual(get_publish_base_url(),
                         (f"{self.dcar_url}/{self.s3_report_bucket}/container-scan-reports/"
                         f"{self.project_name}/{get_datetime()}_{self.job_id}"))

    def test_get_datetime(self):
        from pipeline.common import get_datetime
        from datetime import datetime

        test_date = get_datetime()
        test_date_object = datetime.strptime(test_date, '%Y-%m-%dT%H:%M:%S.%f')
        self.assertIsInstance(test_date_object, datetime)

    def test_get_root_path(self):
        # This is being run currently as though the branch is master
        from pipeline.common import get_root_path

        self.assertEqual(get_root_path(), f"container-scan-reports/{self.project_name}")

    def test_get_base_bucket_directory_production(self):
        # Very similar to the above function, this is being run as though the branch is master
        from pipeline.common import get_base_bucket_directory

        self.assertEqual(get_base_bucket_directory(), "container-scan-reports")

    @mock.patch.object(common, "is_production_branch", mock.Mock(return_value=False))
    def test_get_base_bucket_directory_not_production(self):
        # Very similar to the above function, this is being run as though the branch is master
        from pipeline.common import get_base_bucket_directory

        self.assertEqual(get_base_bucket_directory(), "testing/container-scan-reports")

    @mock.patch.object(common, "get_base_bucket_directory", mock.Mock(return_value="testing/container-scan-reports"))
    def test_get_base_bucket_directory_feature(self):
        from pipeline import common
        self.assertEqual(common.get_base_bucket_directory(), "testing/container-scan-reports")

    def test_is_production_branch(self):
        # Reading from env and the CI_COMMIT_BRANCH - currently is master
        from pipeline.common import is_production_branch
        branch = os.environ["CI_COMMIT_BRANCH"]
        if branch == "master" or branch == "development":
            self.assertTrue(is_production_branch())
        else:
            self.assertFalse(is_production_branch())

    def test_get_git_url(self):
        from pipeline.common import get_git_url

        self.assertEqual(get_git_url(), os.environ.get('CI_SERVER_URL'))

    def test_set_image_version(self):
        from pipeline.common import set_image_version, get_image_version

        set_image_version(self.test_image_version)
        self.assertEqual(get_image_version(), self.test_image_version)

    def test_get_tar_filename(self):
        from pipeline.common import get_tar_filename, get_image_version, set_image_version

        set_image_version(self.test_image_version)
        self.assertEqual(get_tar_filename(),
                         f"{self.project_name}-{get_image_version()}-reports-signature.tar.gz")

    @mock.patch.object(common, "get_image_version", mock.Mock(return_value=None))
    def test_get_tar_filename_if_none(self):
        from pipeline.common import get_tar_filename
        with self.assertRaises(NameError):
            get_tar_filename()

    def test_get_image_signature_filename(self):
        from pipeline.common import get_image_signature_filename, set_image_version, get_image_version

        set_image_version(self.test_image_version)
        self.assertEqual(get_image_signature_filename(), f"{self.project_name}-{get_image_version()}.sig")

    @mock.patch.object(common, "get_image_version", mock.Mock(return_value=None))
    def test_get_image_signature_filename_if_none(self):
        from pipeline.common import get_image_signature_filename
        with self.assertRaises(NameError):
            get_image_signature_filename()

    def test_get_image_filename(self):
        from pipeline.common import get_image_filename, set_image_version, get_image_version

        set_image_version(self.test_image_version)
        self.assertEqual(get_image_filename(), f"{self.project_name}-{get_image_version()}.tar")

    @mock.patch.object(common, "get_image_version", mock.Mock(return_value=None))
    def test_get_image_filename_if_none(self):
        from pipeline.common import get_image_filename
        with self.assertRaises(NameError):
            get_image_filename()

    def test_get_image_version(self):
        from pipeline.common import get_image_version, set_image_version

        if not get_image_version():
            set_image_version(self.test_image_version)
        self.assertEqual(get_image_version(), self.test_image_version)

    @mock.patch.object(common, "_IMAGE_VERSION", None)
    def test_get_image_version_if_none(self):
        from pipeline.common import get_image_version
        with self.assertRaises(NameError):
            get_image_version()

    def test_get_lockname(self):
        from pipeline.common import get_lockname

        self.assertEqual(get_lockname(), self.lock_url)

    def test_get_simple_image_path(self):
        from pipeline.common import get_simple_image_path

        self.assertEqual(get_simple_image_path(), f"{self.project_name}/{self.project_name}")

    def test_get_tag_master(self):
        from pipeline.common import get_tag, set_image_version, get_image_version

        set_image_version(self.test_image_version)

        self.assertEqual(get_tag(), f"{get_image_version()}")

    @mock.patch.object(common, '_CURRENT_BRANCH', "development")
    def test_get_tag_development(self):

        common.set_image_version(self.test_image_version)

        self.assertEqual(common.get_tag(), f"{common.get_image_version()}-development")

    @mock.patch.object(common, '_CURRENT_BRANCH', "feature-branch")
    def test_get_tag_feature_branch(self):
        common.set_image_version(self.test_image_version)

        self.assertEqual(common.get_tag(), f"{common.get_image_version()}-testing")

    def test_get_public_image_tag(self):
        from pipeline.common import get_public_image_tag, set_image_version, get_simple_image_path, get_tag

        set_image_version(self.test_image_version)
        self.assertEqual(get_public_image_tag(), f"{get_simple_image_path()}:{get_tag()}")


if __name__ == '__main__':
    unittest.main()