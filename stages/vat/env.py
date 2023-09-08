import functools
import os
from dataclasses import dataclass

from common.utils import logger

log: logger = logger.setup("Environment")


# pylint: disable=too-many-public-methods
@dataclass
class Environment:
    """A class to represent the CI/CD environment variables.

    This class is designed to use decorators for fetching environment
    variables based on method names. Each method represents an
    environment variable, and when it's accessed, the corresponding
    environment variable is fetched. If the environment variable is not
    set, the system will log the missing variable and its description.
    Optionally, set 'required=True' and the method with raise a
    KeyError. Additionally, the default value can be overridden using
    'default='.
    """

    @staticmethod
    def fetch_env_var(method):
        """Add this wrapper to use a method to get and environment variable."""

        # pylint: disable=protected-access
        @functools.wraps(method)
        def wrapper(self, default="", required=False):
            caller_name = method.__name__
            docstring = method.__doc__
            return self._get_environment_variable(
                default, required, caller_name, docstring
            )

        return wrapper

    def _get_environment_variable(self, default, required, caller_name, docstring):
        env_var = os.environ.get(caller_name.upper(), default)

        log_msg = f"Environment variable {caller_name.upper()} is not set."
        log_msg += f"\n{caller_name.upper()}: {docstring}"

        if env_var == "":
            if required is True:
                log.error(log_msg)
                raise KeyError
            log.info(log_msg)

        return env_var

    @fetch_env_var
    def ci_job_url(self, default: str = "", required: bool = False) -> str:
        """Job details URL.

        Source
        ------
        Gitlab Predefined Variable
        """

    @fetch_env_var
    def base_image_type(self, default: str = "", required: bool = False) -> str:
        """Base image for the image being scanned.

        Source
        ------
        Hardening Manifest
        Pulled from the image itself
        labels.mil.dso.ironbank.os-type
        Set by inspect_image.py using Gitlab dynamic environmental variables
        """

    @fetch_env_var
    def pipeline_repo_dir(self, default: str = "", required: bool = False) -> str:
        """Directory for this repository.

        Source
        ------
        Gitlab Configuration
        globals.yaml
        """

    @fetch_env_var
    def oscap_scans(self, default: str = "", required: bool = False) -> str:
        """Path for OpenSCAP stage artifacts.

        Source
        ------
        Gitlab Configuration
        trigger.yaml
        """

    @fetch_env_var
    def image_to_scan(self, default: str = "", required: bool = False) -> str:
        """Name of the image to scan.

        Source
        ------
        Scan Logic Stage Artifact
        """

    @fetch_env_var
    def scap_url(self, default: str = "", required: bool = False) -> str:
        """The URI to download scap content from.

        Source
        ------
        Unknown, probably does not exist.
        """

    @fetch_env_var
    def docker_auth_file_pull(self, default: str = "", required: bool = False) -> str:
        """Docker permissions as a file.

        Source
        ------
        Gitlab Variable
        varible set in the dsop group
        """

    @fetch_env_var
    def skip_openscap(self, default: str = "", required: bool = False) -> str:
        """If the OpenSCAP scans should be skipped.

        Source
        ------
        Gitlab Configuration
        various templates
        """

    ###
    # Required
    ###

    @fetch_env_var
    def ci_job_id(self) -> str:
        """Pipeline job ID.

        Source
        ------
        Gitlab Configuration
        various templates
        """

    @fetch_env_var
    def build_date(self) -> str:
        """Scan date for pipeline run.

        Source
        ------
        Build stage
        Set by build.py using Gitlab dynamic environmental variables
        """

    @fetch_env_var
    def build_date_to_scan(self) -> str:
        """Build date for pipeline run.

        Source
        ------
        Scan logic Stage
        Set by scan_logic_jobs.py using Gitlab dynamic environmental variables
        """

    @fetch_env_var
    def commit_sha_to_scan(self) -> str:
        """Commit hash for container build.

        Source
        ------
        Scan logic Stage
        Set by scan_logic_jobs.py using Gitlab dynamic environmental variables
        """

    @fetch_env_var
    def image_name(self) -> str:
        """Container VENDOR/PRODUCT/CONTAINER.

        Source
        ------
        Build stage
        Set by build.py using Gitlab dynamic environmental variables
        """

    @fetch_env_var
    def image_version(self) -> str:
        """Container Version from VENDOR/PRODUCT/CONTAINER/VERSION format.

        Source
        ------
        Stargate stage
        set by stargate.py using Gitlab dynamic environmental variables
        """

    @fetch_env_var
    def digest_to_scan(self) -> str:
        """Container Digest as SHA256 Hash.

        Source
        ------
        Scan logic Stage
        Set by scan_logic_jobs.py using Gitlab dynamic environmental variables
        """

    @fetch_env_var
    def oscap_compliance_url(self) -> str:
        """Link to openscap compliance reports directory.

        Source
        ------
        Gitlab Configuration
        various templates
        """

    @fetch_env_var
    def artifact_storage(self) -> str:
        """Environment variable storage.

        Source
        ------
        Set by templates sharedvars.yaml
        """

    ###
    # Optional
    ###

    @fetch_env_var
    def vat_backend_url(self) -> str:
        """Url for API POST.

        Source
        ------
        Notifier scripts
        Set by the notifier.py using Gitlab dynamic environmental variables
        """

    @fetch_env_var
    def base_image(self) -> str:
        """Parent VENDOR/PRODUCT/CONTAINER.

        Source
        ------
        Hardening manifest
        """

    @fetch_env_var
    def base_tag_parent_version(self) -> str:
        """Parent Version from VENDOR/PRODUCT/CONTAINER/VERSION format.

        Source
        ------
        """

    @fetch_env_var
    def ci_project_url(self) -> str:
        """The HTTP(S) address of the project..

        Source
        ------
        Gitlab Configuration
        various templates
        """

    @fetch_env_var
    def use_json_for_vat(self) -> str:
        """Whether to use predefined payload for VAT job.

        Source
        ------
        Gitlab Variable
        currently not set
        """
