from dataclasses import dataclass
import requests
import sys
import logging


@dataclass
class API:
    # maybe use urllib type?
    url: str
    auth: str = ""
    response: requests.Response = None
    app: str = ""
    # data: any = {}
    # params: dict = {}
    # headers: dict = {}

    # check that url is valid using urllib
    # def validate_url():

    # update formatting for url if valid
    # def format_url()

    # confirm data type is either str or json
    # confirm data is valid json
    # def validate_data():


def request_error_handler(func):
    def _request_error_handler(self, *args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.HTTPError:
            if self.response.status_code == 404:
                logging.warning(
                    f"{kwargs.get('image_name')}:{kwargs.get('image_tag')} not found in {self.app}"
                )
                logging.warning(self.response.text)
            elif self.response.status_code == 400:
                logging.warning(f"Bad request: {self.url}")
                logging.warning(self.response.text)
            else:
                logging.warning(
                    f"Unknown response from VAT {self.response.status_code}"
                )
                logging.warning(self.response.text)
                logging.warning(
                    "Failing the pipeline due to an unexpected response from the vat findings api. Please open an issue in this project using the `Pipeline Failure` template to ensure that we assist you. If you need further assistance, please visit the `Team - Iron Bank Pipelines and Operations` Mattermost channel."
                )
        except requests.exceptions.RequestException:
            logging.exception(f"Could not access VAT API: {self.url}")
        except Exception as e:
            logging.exception(f"Unexpected exception thrown {e}")
        finally:
            return self.response

    return _request_error_handler


@dataclass
class VAT_API(API):
    app: str = "VAT"
    container_route: str = "/p1/container"
    import_route: str = "/internal/import"
    import_scan_route: str = f"{import_route}/scan"
    import_artifacts_route: str = f"{import_route}/artifacts"

    @request_error_handler
    def _get_container(self, image_name, image_tag) -> dict:
        logging.info("Running query to vat api")
        self.response = requests.get(
            f"{self.url}{self.container_route}",
            params={"name": image_name, "tag": image_tag},
        )
        self.response.raise_for_status()
        logging.info("Fetched data from vat successfully")
        if self.response.status_code not in [200, 404]:
            sys.exit(1)
        return self.response

    @request_error_handler
    def _force_400(self) -> dict:
        logging.info("Forcing 400")
        self.response = requests.post(
            url=f"{self.url}{self.import_scan_route}",
        )
        self.response.raise_for_status()
        if self.response.status_code not in [201]:
            sys.exit(1)
        return self.response
