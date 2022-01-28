import os
import sys
import pytest
import yaml
import pathlib
import base64


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from downloader import download_all_resources, resource_type  # noqa E402
import downloader  # noqa E402


@pytest.fixture
def mock_docker_resources():
    return {
        "resources": [
            {
                "auth": {"type": "basic"},
                "tag": "registry.access.redhat.com/ubi8:8.5",
                "url": "docker://registry.access.redhat.com/ubi8/ubi@sha256:060d7d6827b34949cc0fc58a50f72a5dccf00a4cc594406bdf5982f41dfe6118",
            },
            {
                "tag": "registry.access.redhat.com/ubi8:8.5",
                "url": "docker://registry.access.redhat.com/ubi8/ubi@sha256:060d7d6827b34949cc0fc58a50f72a5dccf00a4cc594406bdf5982f41dfe6118",
            },
        ]
    }


@pytest.fixture
def mock_github_resources():
    return {
        "resources": [
            {
                "tag": "abc",
                "url": "docker.pkg.github.com/abc",
            },
            {
                "tag": "xyz",
                "url": "https://ghcr.io/xyz",
            },
        ]
    }


@pytest.fixture
def mock_bad_auth_type():
    return {
        "resources": [
            {
                "auth": {"type": "anything_else"},
                "tag": "registry.access.redhat.com/ubi8:8.5",
                "url": "docker://registry.access.redhat.com/ubi8/ubi@sha256:060d7d6827b34949cc0fc58a50f72a5dccf00a4cc594406bdf5982f41dfe6118",
            },
        ]
    }


@pytest.fixture
def mock_downloads():
    with pathlib.Path(
        os.getcwd(), "stages", "import-artifacts", "tests", "mhm.yaml"
    ).open() as f:
        return yaml.safe_load(f)


@pytest.fixture
def mock_artifacts_path():
    return "/path/fakepath"


@pytest.fixture
def mock_urls():
    return {
        "docker_string": "docker://",
        "http_string": "http",
        "s3_string": "s3://",
        "github_string_deprecated": "docker.pkg.github.com/",
        "github_string_current": "https://ghcr.io",
    }


def test_resource_type(mock_urls):
    assert resource_type(mock_urls["docker_string"]) == "docker"
    assert resource_type(mock_urls["http_string"]) == "http"
    assert resource_type(mock_urls["s3_string"]) == "s3"
    assert resource_type(mock_urls["github_string_deprecated"]) == "github"
    assert resource_type(mock_urls["github_string_current"]) == "github"
    assert resource_type("") == "Error in parsing resource type."


def test_download_all_resources(
    monkeypatch,
    mock_docker_resources,
    mock_github_resources,
    mock_bad_auth_type,
    mock_artifacts_path,
):
    def mock_resource_type_docker(*args, **kwargs):
        return "docker"

    def mock_resource_type_github(*args, **kwargs):
        return "github"

    def mock_pull_image(*args, **kwargs):
        return None

    def mock_b64decode(*args, **kwargs):
        return "random".encode()

    def mock_get_auth(*args, **kwargs):
        return ("blah", "blah")

    monkeypatch.setattr(downloader, "resource_type", mock_resource_type_docker)
    monkeypatch.setattr(downloader, "pull_image", mock_pull_image)
    monkeypatch.setattr(downloader, "get_auth", mock_get_auth)

    assert not download_all_resources(mock_docker_resources, mock_artifacts_path)

    monkeypatch.setattr(downloader, "resource_type", mock_resource_type_github)

    os.environ["GITHUB_ROBOT_USER"] = base64.b64encode("random".encode()).decode()
    os.environ["GITHUB_ROBOT_TOKEN"] = base64.b64encode("random".encode()).decode()

    assert not download_all_resources(mock_github_resources, mock_artifacts_path)

    with pytest.raises(SystemExit) as exitInfo:
        download_all_resources(mock_bad_auth_type, mock_artifacts_path)

    assert exitInfo.type == SystemExit
    assert exitInfo.value.code
