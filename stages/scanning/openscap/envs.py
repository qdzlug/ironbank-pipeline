import os
from log import log

# TODO: move the envs


def fetch_env_var(func_name: str, docstring: str, default: str = "") -> str:
    """Gets the env or returns the default"""
    uppercase_name = func_name.upper()
    env = os.getenv(uppercase_name, default)

    if not env:
        log_msg = f"Environment variable {uppercase_name} is not set."
        if docstring:
            log_msg += f"\n{uppercase_name}: {docstring}"
        log.info(log_msg)

    return env


def ci_var(func=None, *, default: str = ""):
    """
    Decorator to fetch corresponding environment variable for a function's name.

    Examples
    --------
    class Config:
        @ci_var
        def database_url(self) -> str:
            "This would fetch DATABASE_URL from environment variables."

        @ci_var(default="localhost")
        def database_host(self) -> str:
            "This would fetch DATABASE_HOST or default to 'localhost'."
    """
    if func:
        return property(
            lambda instance: fetch_env_var(func.__name__, func.__doc__, default)
        )

    return lambda func: property(
        lambda instance: fetch_env_var(func.__name__, func.__doc__, default)
    )


# pylint: disable=missing-function-docstring
class Envs:
    """
    A class to represent the CI/CD environment variables.

    This class is designed to use decorators for fetching environment variables based on method names.
    Each method represents an environment variable, and when it's accessed, the corresponding
    environment variable is fetched. If the environment variable is not set, the system will log
    the missing variable and its description.

    Notes
    -----
    While the method docstrings describe the purpose and source of each environment
    variable, the methods don't execute any functional logic. Instead, when accessed,
    the `ci_var` decorator ensures the environment variable corresponding to the method
    name is fetched. If a default value is provided and the environment variable doesn't exist,
    the default value will be returned.
    """

    @ci_var
    def ci_job_url(self) -> str:
        """
        Job details URL

        Source
        ------
        Gitlab Predefined Variable
        """

    @ci_var
    def base_image_type(self) -> str:
        """
        Base image for the image being scanned

        Source
        ------
        Hardening Manifest
        Pulled from the image itself
        labels.mil.dso.ironbank.os-type
        Set by inspect_image.py using Gitlab dynamic environmental variables
        """

    @ci_var
    def pipeline_repo_dir(self) -> str:
        """
        Directory for this repository

        Source
        ------
        Gitlab Configuration
        globals.yaml
        """

    @ci_var
    def oscap_scans(self) -> str:
        """
        Path for OpenSCAP stage artifacts

        Source
        ------
        Gitlab Configuration
        trigger.yaml
        """

    @ci_var
    def image_to_scan(self) -> str:
        """
        Name of the image to scan

        Source
        ------
        Scan Logic Stage Artifact
        """

    @ci_var
    def scap_url(self) -> str:
        """
        The URI to download scap content from

        Source
        ------
        Unknown, probably does not exist.
        """

    @ci_var
    def docker_auth_file_pull(self) -> str:
        """
        Docker permissions as a file

        Source
        ------
        Gitlab Variable
        varible set in the dsop group
        """

    @ci_var(default="0")
    def skip_openscap(self) -> str:
        """
        If the OpenSCAP scans should be skipped

        Source
        ------
        Gitlab Configuration
        various templates
        """
