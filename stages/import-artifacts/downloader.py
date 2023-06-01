#!/usr/bin/env python3

import sys
from subprocess import CalledProcessError
from urllib.parse import urlparse
from botocore.exceptions import ClientError
from requests.exceptions import HTTPError

from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.exceptions import (
    GenericSubprocessError,
    InvalidURLList,
    ArtifactNotFound,
)
from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.abstract_artifacts import AbstractFileArtifact
from ironbank.pipeline.artifacts import (
    HttpArtifact,
    S3Artifact,
    ContainerArtifact,
    GithubArtifact,
)

log = logger.setup("import_artifacts")


def get_artifact_type(resource, scheme, netloc):
    github_current = "ghcr.io"
    github_deprecated = "docker.pkg.github.com"

    if "s3" in scheme:
        artifact = S3Artifact(**resource)
    elif github_current in netloc:
        artifact = GithubArtifact(**resource)
    elif github_deprecated in netloc:
        log.warning(
            "{github_deprecated} has been deprecated. Please switch to {github_current} when possible."
        )
        artifact = GithubArtifact(**resource)
    elif "docker" in scheme:
        artifact = ContainerArtifact(**resource)
    elif "http" in scheme:
        artifact = HttpArtifact(**resource)
    else:
        raise ArtifactNotFound

    return artifact


def set_artifact_path(artifact):
    if isinstance(artifact, AbstractFileArtifact):
        artifact.dest_path = artifact.dest_path / "external-resources"
        artifact.artifact_path = artifact.dest_path / artifact.filename
    elif isinstance(artifact, ContainerArtifact):
        artifact.dest_path = artifact.dest_path / "images"
        artifact.artifact_path = (
            artifact.dest_path
            / f"{artifact.tag.replace('/', '-').replace(':', '-')}.tar"
        )
    return artifact


def main():
    """Main function."""

    # Read hardening_manifest.yaml file
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)

    # we probably don't need this, but maybe we want to validate it in case it somehow changes state before import?
    # hardening_manifest.validate()
    if not hardening_manifest.resources:
        log.info("No resources in %s", hardening_manifest.resources)
        sys.exit(0)
    exit_code = 1
    artifact = None
    try:
        # TODO: refactor into a separate function
        for resource in hardening_manifest.resources:
            parsed_url = (
                urlparse(resource["url"])
                if "url" in resource
                else urlparse(resource["urls"][0])
            )
            scheme = parsed_url.scheme
            netloc = parsed_url.netloc
            artifact_type = get_artifact_type(resource, scheme, netloc)
            artifact = set_artifact_path(artifact_type)
            # download also gathers any relevant auth and runs any pre download validation
            artifact.download()
            if isinstance(artifact, AbstractFileArtifact):
                artifact.validate_checksum()
            log.info("")
        # all resources are downloaded successfully
        exit_code = 0
    except ArtifactNotFound:
        log.error("Invalid scheme %s for artifact %s", scheme, resource["url"])
    except KeyError as ke:
        log.error("The following key does not have a value: %s", ke)
    except AssertionError as ae:
        log.error("Assertion Error: %s", ae)
    except InvalidURLList:
        log.error(
            "No valid urls provided for %s. Please ensure the url(s) for this resource exists and is not password protected. If you require basic authentication to download this resource, please open a ticket in this repository.",
            artifact.filename,
        )
    except HTTPError as he:
        log.error(
            "Error downloading %s, Status code: %s",
            artifact.url,
            he.response.status_code,
        )
    except ClientError:
        log.error("S3 client error occurred")
    except (CalledProcessError, GenericSubprocessError):
        log.error(
            "Resource failed to pull, please check hardening_manifest.yaml configuration"
        )
    except RuntimeError:
        log.error("Unexpected runtime error occurred.")
    except Exception as e:  # pylint:  disable=broad-except
        log.error("Unexpected error occurred. Exception class: %s", e.__class__)
    finally:
        if artifact is not None and exit_code == 1:
            artifact.delete_artifact()
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
