import os
import requests
import subprocess
import functools
from ironbank.pipeline.utils.exceptions import (
    GenericSubprocessError,
    MaxRetriesException,
)
from ironbank.pipeline.utils import logger

log: logger = logger.setup(name="Exception")


def request_retry(retry_count):
    """
    Decorator for retrying a function running a subprocess call
    """

    def decorate(func):
        # self, args and kwargs are passed to allow this decorator to work on any method
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            for retry_num in range(1, retry_count + 1):
                try:
                    return func(self, *args, **kwargs)
                except subprocess.CalledProcessError:
                    if retry_num >= retry_count:
                        # prevent exception chaining by using from None
                        raise MaxRetriesException() from None
                    else:
                        self.log.warning("Resource failed to pull, retrying...")

        return wrapper

    return decorate


def key_index_error_handler(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except KeyError as ke:
            self._log.debug(f"KeyError: No key for {ke.args[0]}")
        except IndexError as ie:
            self._log.debug(f"IndexError: {ie.args[0]}")

    return wrapper


def subprocess_error_handler(logging_message: str):
    def decorate(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except subprocess.CalledProcessError:
                log.error(logging_message)
                # prevent exception chaining by using from None
                raise GenericSubprocessError() from None
            except subprocess.SubprocessError:
                log.error(logging_message)
                # prevent exception chaining by using from None
                raise GenericSubprocessError() from None

        return wrapper

    return decorate


def request_error_handler(func):
    @functools.wraps(func)
    def wrapper(self, image_name: str = "", *args, **kwargs):
        try:
            return func(self, image_name, *args, **kwargs)
        except requests.exceptions.HTTPError:
            if self.response.status_code == 400:
                self.log.warning(f"Bad request: {self.url}")
                self.log.warning(self.response.text)
            elif self.response.status_code == 403:
                self.log.warning(
                    f"{os.environ['CI_PROJECT_NAME']} is not authorized to use the image name of: {image_name}. Either the name has changed or the container has never been tracked in VAT. An authorization request has automatically been generated. Please create a ticket with the link below for VAT authorization review."
                )
                self.log.info(
                    f"https://repo1.dso.mil/dsop/dccscr/-/issues/new?issuable_template=VAT%20Pipeline%20Access%20Request&issue[title]=VAT+Pipeline+Access+Request+{os.environ['CI_PROJECT_URL']}"
                )
            else:
                self.log.warning(
                    f"Unknown response from VAT {self.response.status_code}"
                )
                self.log.warning(self.response.text)
                self.log.warning(
                    "Failing the pipeline due to an unexpected response from the vat findings api. Please open an issue in this project using the `Pipeline Failure` template to ensure that we assist you. If you need further assistance, please visit the `Team - Iron Bank Pipelines and Operations` Mattermost channel."
                )
        except requests.exceptions.RequestException:
            self.log.warning(f"Could not access VAT API: {self.url}")
        except RuntimeError as runerr:
            self.log.warning(f"Unexpected exception thrown {runerr}")

    return wrapper
