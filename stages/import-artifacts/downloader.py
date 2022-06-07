#!/usr/bin/env python3

import os
import sys
import logging
from urllib.parse import urlparse
import subprocess
from botocore.exceptions import ClientError
from requests.exceptions import HTTPError

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)
from utils import logger  # noqa E402
from utils.exceptions import InvalidURLList  # noqa E402
from project import DsopProject  # noqa E402
from hardening_manifest import HardeningManifest  # noqa E402
from artifacts import (  # noqa E402
    HttpArtifact,
    S3Artifact,
    ContainerArtifact,
    GithubArtifact,
    FileArtifact,
)

log = logger.setup("import_artifacts")


def main():

    # Read hardening_manifest.yaml file
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)

    # we probably don't need this, but maybe we want to validate it in case it somehow changes state before import?
    # hardening_manifest.validate()
    if not hardening_manifest.resources:
        logging.info(f"No resources in {hardening_manifest.resources}")
        sys.exit(0)
    exit_code = 1
    artifact = None
    try:
        for resource in hardening_manifest.resources:
            scheme = urlparse(resource["url"]).scheme

            github_current = "ghcr.io"
            github_deprecated = "docker.pkg.github.com/"
            if "docker" in scheme:
                artifact = ContainerArtifact(**resource)
            elif "s3" in scheme:
                artifact = S3Artifact(**resource)
            elif github_current in scheme:
                artifact = GithubArtifact(**resource)
            elif github_deprecated in scheme:
                logging.warn(
                    "{github_deprecated} has been deprecated. Please switch to {github_current} when possible."
                )
                artifact = GithubArtifact(**resource)
            elif "http" in scheme:
                artifact = HttpArtifact(**resource)
            else:
                log.error(f"Invalid scheme {scheme}")

            # download also gathers any relevant auth and runs any pre download validation
            artifact.download()
            if isinstance(artifact, FileArtifact):
                artifact.validate_checksum()
        # all resources are downloaded successfully
        exit_code = 0
    except KeyError as ke:
        logging.error(f"The following key does not have a value: {str(ke)}")
    except AssertionError as ae:
        logging.error(f"Assertion Error: {ae}")
    except InvalidURLList:
        logging.error(
            f"No valid urls provided for {artifact.filename}. Please ensure the url(s) for this resource exists and is not password protected. If you require basic authentication to download this resource, please open a ticket in this repository."
        )
    except HTTPError as he:
        logging.debug(
            f"Error downloading {artifact.url}, Status code: {he.response.status_code}"
        )
    except ClientError:
        logging.error("S3 client error occurred")
    except subprocess.CalledProcessError:
        logging.error(
            "Resource failed to pull, please check hardening_manifest.yaml configuration"
        )
    except RuntimeError as rune:
        logging.error(
            f"Unexpected runtime error occurred. Exception class: {rune.__class__}"
        )
    except Exception as e:
        logging.error(f"Unexpected error occurred. Exception class: {e.__class__}")
    finally:
        if exit_code == 1:
            artifact.delete_artifact()
        sys.exit(exit_code)

    # more exceptions


if __name__ == "__main__":
    main()
