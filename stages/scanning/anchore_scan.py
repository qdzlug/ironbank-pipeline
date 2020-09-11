#!/usr/bin/env python3
import re
import requests
import json
import os
import sys



class Anchore():
    """
    Anchore Scanner

    """

    def __init__(self, url, username, password, verify, image, output, imageid, debug):
        self.url      = url
        self.username = username
        self.password = password
        self.verify   = verify
        self.image    = image
        self.output   = output
        self.imageid  = imageid
        self.debug    = debug


    def __debug(self, msg):
        """
        Internal debug printer

        """
        if self.debug:
            print(f"DEBUG:  {msg}")


    def __get_anchore_api_json(self, url, payload = ""):
        """
        Internal api response fetcher. Will check for a valid return code and
        ensure the response has valid json. Once everything has been validated
        it will return a dictionary of the json.

         payload - request payload for anchore api

        """
        self.__debug(f"Fetching {url}")
        try:
            r = requests.get(
                    url,
                    auth   = (self.username, self.password),
                    params = payload,
                    verify = self.verify
            )
            body = r.text

            if r.status_code == 200:
                # test that the response is valid JSON
                self.__debug(f"Got response from Anchore. Testing if valid json")
                try:
                    json.loads(body)
                except:
                    raise Exception("Got 200 response but is not valid JSON")
            else:
                raise Exception(f"Non-200 response recieved from Anchore {str(r.status_code)} - {r.text}")
        except Exception as err:
            raise err

        self.__debug(f"Json is valid")
        return json.loads(body)


    def get_version(self):
        """
        Fetch the Anchore version and write it to an artifact.

        """
        print(f"Getting Anchore version")
        url = f"{self.url}/version"
        version_json = self.__get_anchore_api_json(url)
        filename = os.path.join(self.output, "anchore-version.txt")
        self.__debug(f"Writing to {filename}")
        with open(filename, "w") as f:
            json.dump(version_json["service"]["version"], f)


    def get_vulns(self):
        """
        Fetch the vulnerability data for the scanned image. Will parse the
        vulnerability response and look for VulnDB records. When a VulnDB record
        is found, the URL points to a pod name which is not publicly accessible
        so it will reach back out to Anchore to gather the correct vulnerability data.

        """
        print(f"Getting vulnerability results")
        try:
            vuln_dict = self.__get_anchore_api_json(f"{self.url}/images/by_id/{self.imageid}/vuln/all")

            for vulnerability in vuln_dict['vulnerabilities']:
                # If VulnDB record found, retrive set of reference URLs associated with the record.
                if (vulnerability["feed_group"] == "vulndb:vulnerabilities"):
                    # "http://anchore-anchore-engine-api:8228/v1" or URL to replace may
                    #  need to be modified when changes to the Anchore installation occur
                    vulndb_request_url = re.sub("http:\/\/([a-z-_0-9:]*)\/v1", self.url, vulnerability["url"])
                    vulndb_dict = self.__get_anchore_api_json(vulndb_request_url)
                    for vulndb_vuln in vulndb_dict["vulnerabilities"]:
                        vulnerability['url'] = vulndb_vuln["references"]

            vuln_dict["imageFullTag"] = self.image
            # Create json report called anchore_security.json
            try:
                filename = os.path.join(self.output, 'anchore_security.json')
                self.__debug(f"Writing to {filename}")
                with open(filename, 'w') as fp:
                    json.dump(vuln_dict, fp)

            except Exception as err:
                raise err

        except Exception as err:
            # if any report fails, raise the error and failstop program
            raise err


    def get_compliance(self):
        """
        Fetch the compliance results for the Anchore policy bundle. Will write
        out the actual API response that contains the results, along with the
        subset of the results that was previously used to parse into the findings
        spreadsheet.

        """
        print(f"Getting compliance results")
        request_url = f"{self.url}/images/by_id/{self.imageid}/check?tag={self.image}&detail=true"
        body_json = self.__get_anchore_api_json(request_url)

        # Save the API response
        filename = os.path.join(self.output, "anchore_api_gates_full.json")
        self.__debug(f"Writing to {filename}")
        with open(filename, "w") as f:
            json.dump(body_json, f)

        digest = list(body_json[0].keys())[0]
        results = body_json[0][digest][self.image][0]["detail"]["result"]["result"]

        # Grab the subset of data used in anchore_gates.json
        results_dict = dict()
        results_dict[self.imageid] = results[self.imageid]

        filename = os.path.join(self.output, "anchore_gates.json")
        self.__debug(f"Writing to {filename}")
        with open(filename, "w") as f:
            json.dump(results_dict, f)




def main():

    endpoint_url = re.sub("\/+$", '', os.getenv("ANCHORE_CLI_URL", default = "http://localhost:8228/v1/"))

    anchore = Anchore(
            url      = endpoint_url,
            username = os.getenv("ANCHORE_CLI_USER",       default = "admin"),
            password = os.getenv("ANCHORE_CLI_PASS",       default = "foobar"),
            verify   = os.getenv("ANCHORE_VERIFY",         default = True),
            image    = os.getenv("IMAGE_NAME",             default = "none"),
            output   = os.getenv("ANCHORE_SCAN_DIRECTORY", default = "."),
            imageid  = os.getenv("IMAGE_ID",               default = "none"),
            debug    = os.getenv("ANCHORE_DEBUG",          default = False),
    )

    anchore.get_vulns()
    anchore.get_compliance()
    anchore.get_version()



if __name__ == "__main__":
    sys.exit(main())

