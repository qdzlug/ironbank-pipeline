import os
import unittest
import boto3
from unittest import TestCase
from unittest import mock
from datetime import datetime
from pipeline import common
from pipeline import constants

# Set up the Environment Variables
# We must initialize them before importing anything from pipeline,
#    as the constants will be read from os.environ on import
os.environ["CI_SERVER_URL"] = "https://repo1.dsop.io"
os.environ["CI_JOB_ID"] = "999"
os.environ["CI_PROJECT_NAME"] = "test_project"
os.environ["CI_COMMIT_BRANCH"] = "master"
os.environ["CI_PROJECT_URL"] = "https://repo1.dsop.io/test/test_project"
os.environ["CI_REPOSITORY_URL"] = "https://registry1.dsop.io/test/test_project"


class TestCommon(TestCase):
    def setUp(self):
        from pipeline.constants import DCAR_URL, S3_REPORT_BUCKET, JOB_ID, PROJECT_NAME, GITLAB_URL, LOCK_URL, CURRENT_BRANCH
        common.set_image_version("1.1.0")
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
        self.base_link = f"https://s3-us-gov-west-1.amazonaws.com/${constants.S3_REPORT_BUCKET}/{common.get_root_path()}/{common.get_image_version()}/{common.get_datetime()}_{constants.JOB_ID}"
        self.test_json = {
            "Repo_Name": self.project_name,
            "Approval_Status": "approval",
            "Public_Key": "key_contents",
            "Image_Sha": "8B7DF143D91C716ECFA5FC1730022F6B421B05CEDEE8FD52B1FC65A96030AD52",
            "Image_Name": constants.PROJECT_NAME,
            "Image_Tag": common.get_image_version(),
            "Image_Path": common.get_image_filename(),
            "Image_URL": f"{self.base_link}/reports/{common.get_image_filename()}",
            "Build_Number": constants.JOB_ID,
            "Image_Manifest": f"{self.base_link}/{constants.MANIFEST_FILENAME}",
            "Manifest_Name":   f"{constants.MANIFEST_FILENAME}",
            "PGP_Signature":   f"{self.base_link}/${constants.SIGNATURE_FILENAME}",
            "Signature_Name":  f"{constants.SIGNATURE_FILENAME}",
            "Version_Documentation": f"{self.base_link}/{constants.DOCUMENTATION_FILENAME}",
            "Tar_Location": f"{self.base_link}/{common.get_tar_filename()}",
            "Tar_Name": common.get_tar_filename(),
            "OpenSCAP_Compliance_Results": f"{self.base_link}/${constants.CSV_DIRECTORY}/oscap.csv",
            "OpenSCAP_OVAL_Results": f"{self.base_link}/${constants.CSV_DIRECTORY}/oval.csv",
            "TwistLock_Results": f"{self.base_link}/${constants.CSV_DIRECTORY}/tl.csv",
            "Anchore_Gates_Results": f"{self.base_link}/${constants.CSV_DIRECTORY}/anchore_gates.csv",
            "Anchore_Security_Results": f"{self.base_link}/${constants.CSV_DIRECTORY}/anchore_security.csv",
            "Summary_Report": f"{self.base_link}/${constants.CSV_DIRECTORY}/summary.csv",
            "Full_Report": f"{self.base_link}/${constants.CSV_DIRECTORY}/all_scans.xlsx"
        }

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

    def test_path_join(self):
        from pipeline.common import path_join
        self.assertEqual(path_join("this/is/a/test/", "path.txt"), self.path)

    @mock.patch.object(common, '_s3_object_exists', mock.Mock(return_value=True))
    @mock.patch.object(common, 'validate_s3_bucket_endpoints', mock.Mock(return_value=[])))
    def test_validate_s3_bucket_endpoints(self):
        from pipeline.common import validate_s3_bucket_endpoints
        common.set_image_version("1.1.0")
        self.assertEqual(validate_s3_bucket_endpoints(self.test_json, "test_bucket"), [])

    def test_validate_aws_region(self):
        from pipeline.common import validate_aws_region
        valid_regions = ['us-west-1', 'us-gov-west-1', 'us-east-2']
        invalid_regions = ['mother-dearest', 'this_is_wrong', 'inVaLiD.Char\\s']
        for region in valid_regions:
            self.assertTrue(validate_aws_region(region))
        for region in invalid_regions:
            self.assertFalse(validate_aws_region(region))

    def test_path_join(self):
        from pipeline.common import path_join
        self.assertEqual(path_join("this/is/a/test/", "path.txt"), self.path)

    @mock.patch.object(common, '_s3_object_exists', mock.Mock(return_value=True))
    @mock.patch.object(common, 'validate_s3_bucket_endpoints', mock.Mock(return_value=[])))
    def test_validate_s3_bucket_endpoints(self):
        from pipeline.common import validate_s3_bucket_endpoints
        common.set_image_version("1.1.0")
        self.assertEqual(validate_s3_bucket_endpoints(self.test_json, "test_bucket"), [])

    def test_path_join(self):
        from pipeline.common import path_join
        self.assertEqual(path_join("this/is/a/test/", "path.txt"), self.path)

    @mock.patch.object(common, '_s3_object_exists', mock.Mock(return_value=True))
    @mock.patch.object(common, 'validate_s3_bucket_endpoints', mock.Mock(return_value=[])))
    def test_validate_s3_bucket_endpoints(self):
        from pipeline.common import validate_s3_bucket_endpoints
        common.set_image_version("1.1.0")
        self.assertEqual(validate_s3_bucket_endpoints(self.test_json, "test_bucket"), [])


if __name__ == '__main__':
    unittest.main()
