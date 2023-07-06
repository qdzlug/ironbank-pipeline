import pytest
from moto import mock_sts, mock_s3
import pathlib
import boto3
from ironbank.pipeline.s3_irsa_auth.authenticate import authenticate_client
from unittest.mock import MagicMock


bucket_name = "test-bucket"
object_path = "test-key"
session_name = "test-session"
local_file_path = "test-file"
aws_access_key_id = "test-access-key"
aws_secret_access_key = "test-secret-key"


@pytest.fixture
def aws_credentials(monkeypatch):
    """Mocked AWS Credentials for moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def s3_client(aws_credentials):
    with mock_s3():
        conn = boto3.client("s3", region_name="us-east-1")
        yield conn


@pytest.fixture
def sts_client(aws_credentials):
    with mock_sts():
        conn = boto3.client("sts", region_name="us-east-1")
        yield conn


def mock_open_func(*args, **kwargs):
    return "file contents"


def mock_check_for_latest_objects(*args, **kwargs):
    return "latest key"


class MockAssumeRole:
    def assume_role_with_web_identity(self, **kwargs):
        return {
            "Credentials": {
                "AccessKeyId": "access_key_id",
                "SecretAccessKey": "secret_access_key",
                "SessionToken": "session_token",
            }
        }


@mock_sts
@mock_s3
def test_authenticate_client(monkeypatch, sts_client, caplog):
    # Mock environment variables for AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN
    monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "some/file/path")
    monkeypatch.setenv(
        "AWS_ROLE_ARN",
        "arn:aws-us-gov:iam::111111111111:role/test-gitlab-runner-ironbank-test-role",
    )

    # Mocking the contents of the web identity token file
    monkeypatch.setattr(pathlib.Path, "read_text", mock_open_func)

    sts_client = boto3.client("sts")
    sts_client.meta.events.register(
        "before-call", MockAssumeRole().assume_role_with_web_identity
    )

    # Test the authenticate_client function
    region = "us-east-1"

    authenticate_client(region)
    assert "Authenticated S3 Client" in caplog.text


@mock_sts
@mock_s3
def test_authenticate_client_missing_env_vars(monkeypatch, caplog):
    """Test that the function raises an error when required environment variables are missing."""
    # Remove environment variables
    monkeypatch.delenv("AWS_WEB_IDENTITY_TOKEN_FILE", raising=False)
    monkeypatch.delenv("AWS_ROLE_ARN", raising=False)

    with pytest.raises(KeyError):
        authenticate_client("us-west-1")

    assert "Error while accessing IRSA environment variables" in caplog.text


@mock_sts
@mock_s3
def test_authenticate_client_auth_error(monkeypatch, caplog):
    """Test that the function raises an error when there is a problem authenticating the S3 client."""
    # Set environment variables
    monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "some/file/path")
    monkeypatch.setenv(
        "AWS_ROLE_ARN",
        "arn:aws-us-gov:iam::111111111111:role/test-gitlab-runner-ironbank-test-role",
    )

    # Mock the method to return a dummy token
    monkeypatch.setattr(
        pathlib.Path, "read_text", lambda self, encoding=None: "dummy_token"
    )

    # Mock the assume_role_with_web_identity method to raise an exception
    def mock_assume_role_with_web_identity(*args, **kwargs):
        raise Exception("Mocked authentication error")

    mock_sts_client = MagicMock()
    mock_sts_client.assume_role_with_web_identity = mock_assume_role_with_web_identity

    # Patch 'boto3.client' to use our mock sts client
    monkeypatch.setattr(
        "boto3.client",
        lambda service_name, **kwargs: mock_sts_client
        if service_name == "sts"
        else MagicMock(),
    )

    with pytest.raises(Exception, match="Mocked authentication error"):
        authenticate_client("us-west-2")

    assert "An Error Occured While Authenticating The S3 Client" in caplog.text
