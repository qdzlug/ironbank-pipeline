import os
import unittest
from unittest import TestCase
from mock import patch, mock_open
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
from pipeline.resources.contributor_resource import *

TEST_DOCKER_RESOURCE = {
    "url": "docker://example.com/x/y/app:1.0",
    "tag": "app:1.0",
    "auth": {},
    "tls_verify": True
}

TEST_S3_RESOURCE = {
    "url": "s3://example.com/x/y/file.txt",
    "filename": "file.txt",
    "validation": {
        "type": "sha256",
        "value": "XXXXXX"},
    "auth": {
        "type": "aws",
        "region": "xxxxx"
    }
}

TEST_HTTP_RESOURCE = {
    "url": "https://example.com/x/y/file.txt",
    "filename": "file.txt",
    "validation": {
        "type": "sha256",
        "value": "XXXXXX"
    },
    "auth": {
        "type": "basic",
        "id": "credential-1"
    },
    "tls_verify": True
}

CONTRIBUTOR_OPEN = 'pipeline.resources.contributor_resource.open'


class TestContributorResource(TestCase):
    def setUp(self):
        from pipeline.constants import DCAR_URL, S3_REPORT_BUCKET, JOB_ID, PROJECT_NAME, GITLAB_URL, \
            LOCK_URL, CURRENT_BRANCH
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

    def test_default_attributes(self):
        contributor_resource = ContributorResource()
        self.assertEqual(contributor_resource.internal_docker_repo, '')
        self.assertEqual(contributor_resource.internal_http_repo, '')
        self.assertEqual(contributor_resource.namespace, '')
        self.assertEqual(contributor_resource.context, None)
        self.assertEqual(contributor_resource.validation, None)
        self.assertEqual(contributor_resource.auth, None)
        self.assertEqual(contributor_resource.url, '')

    def test_interface_functions(self):
        contributor_resource = ContributorResource()
        with self.assertRaises(NotImplementedError):
            contributor_resource.upload_resource()
        with self.assertRaises(NotImplementedError):
            contributor_resource.stage_resource()

    def test_url_validation(self):
        """
        Set up enough values to run the function
        """
        valid_url = 'https://google.com'
        invalid_url = 'asdflkj.asdflkj.asdflkj'
        contributor_resource = ContributorResource()
        contributor_resource.url = valid_url

        with self.assertRaises(ValueError):
            contributor_resource.url = invalid_url

class TestContributorResourceAuth(TestCase):
    def test_auth_type(self):
        basic_auth_dict = {'type': 'basic'}
        aws_auth_dict = {'type': 'aws', 'region': 'us-west-2'}
        x509_auth_dict = {'type': 'x509'}
        basic_auth = ContributorResourceAuth(auth_dict=basic_auth_dict)
        aws_auth = ContributorResourceAuth(auth_dict=aws_auth_dict)
        x509_auth = ContributorResourceAuth(auth_dict=x509_auth_dict)

        self.assertEqual(basic_auth.auth_type, basic_auth_dict['type'])
        self.assertEqual(aws_auth.auth_type, aws_auth_dict['type'])
        self.assertEqual(x509_auth.auth_type, x509_auth_dict['type'])

        invalid_auth_dict = {'type': 'invalid'}
        with self.assertRaises(ValueError):
            ContributorResourceAuth(auth_dict=invalid_auth_dict)

    def test_id(self):
        valid_id = 'credentials-1'
        invalid_id = 'credentials{0}'
        invalid_characters = r'<>/{}[\]~ \\,()*&^%$#@!\"\'`~'

        valid_dict = {'type': 'basic', 'id': valid_id}
        invalid_dict = {'type': 'basic', 'id': None}

        default_auth = ContributorResourceAuth(auth_dict={'type': 'basic'})
        self.assertEqual(default_auth.id, 'default-credentials')

        valid_auth = ContributorResourceAuth(auth_dict=valid_dict)
        self.assertEqual(valid_auth.id, valid_id)

        for char in invalid_characters:
            invalid_dict['id'] = invalid_id.format(char)
            with self.assertRaises(ValueError):
                ContributorResourceAuth(auth_dict=invalid_dict)

    def test_region(self):
        valid_region = 'us-west-2'
        invalid_region = 'invalid'

        valid_dict = {'type': 'aws', 'region': valid_region}
        invalid_dict = {'type': 'aws', 'region': invalid_region}

        valid_auth = ContributorResourceAuth(auth_dict=valid_dict)
        self.assertEqual(valid_auth.region, valid_region)

        with self.assertRaises(ValueError):
            ContributorResourceAuth(auth_dict=invalid_dict)





class TestHTTPResource(TestCase):
    def setUp(self):
        self.file_resource = generate_resource(TEST_HTTP_RESOURCE)

    @responses.activate
    def test_stage_resource(self):
        """
        Mock requests/response and call the function
        """
        retval = {
            'json': 'returnvalue'
        }
        responses.add(responses.GET, self.file_resource.internal_http_repo, status=200,
                      body=json.dumps(retval))
        responses.add(responses.GET, self.file_resource.internal_http_repo, status=404,
                      body=json.dumps(retval))
        responses.add(responses.GET, self.file_resource.internal_http_repo, status=200,
                      body='json:invalid')

        # Successful response
        m = mock_open()
        with patch(CONTRIBUTOR_OPEN, new_callable=m):
            self.file_resource.stage_resource()
            # m.assert_called_with()


        # 404 response
        self.file_resource.stage_resource()

        # Successful response with bad data
        self.file_resource.stage_resource()



    def test_stage(self):
        """
        Mock requests/response and call the function
        """
        pass



if __name__ == '__main__':
    unittest.main()
