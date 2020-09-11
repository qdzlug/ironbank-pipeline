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

    def __init__(self, url, username, password, verify, image, output, debugon = True):
        self.url      = url
        self.username = username
        self.password = password
        self.verify   = verify
        self.image    = image
        self.output   = output
        self.debugon  = debugon
        self.digest   = self.__get_image_digest()


    """

    """
    def __debug(self, msg):
        if self.debugon:
            print(msg)

    """

    """
    def __get_anchore_api_json(self, url, payload = ""):
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
                raise Exception("Non-200 response recieved from Anchore " + str(r.status_code) + " - " + r.text)
        except Exception as err:
            raise err

        self.__debug(f"Json is valid")
        return json.loads(body)


    """

    """
    def __get_image_digest(self):
        url = f"{self.url}/images"
        payload = {'fulltag': self.image, 'history': 'false'}
        image_list = self.__get_anchore_api_json(url, payload)
        image_digest = image_list[0]["imageDigest"]
        if image_digest == None:
            raise Exception("Image Digest does not Exist")
        return image_digest



    def get_version(self):
        url = f"{self.url}/version"
        version_json = self.__get_anchore_api_json(url)
        filename = os.path.join(self.output, "anchore-version.txt")
        self.__debug(f"Writing to {filename}")
        with open(filename, "w") as f:
            json.dump(version_json["service"]["version"], f)

    """

    """
    def get_vulns(self):
        try:
            vuln_dict = self.__get_anchore_api_json(f"{self.url}/images/{self.digest}/vuln/all")

            for vulnerability in vuln_dict['vulnerabilities']:
                # If VulnDB record found, retrive set of reference URLs associated with the record.
                if (vulnerability["feed_group"] == "vulndb:vulnerabilities"):
                    # "http://anchore-anchore-engine-api:8228/v1" or URL to replace may need to be modified when changes to the Anchore installation occur
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


    """

    """
    def get_compliance(self):
        request_url = f"{self.url}/images/{self.digest}/check?tag={self.image}&detail=true"
        body_json = self.__get_anchore_api_json(request_url)

        # Save the API response
        filename = os.path.join(self.output, "anchore_api_gates_full.json")
        self.__debug(f"Writing to {filename}")
        with open(filename, "w") as f:
            json.dump(body_json, f)
        imageid = body_json[0][self.digest]["docker.io/" + self.image][0]["detail"]["result"]["image_id"]
        results = body_json[0][self.digest]["docker.io/" + self.image][0]["detail"]["result"]["result"]

        results_dict = dict()

        # Grab the subset of data used in anchore_gates.json
        results_dict[imageid] = results[imageid]

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
            output   = os.getenv("ANCHORE_SCAN_DIRECTORY", default = ".")
    )

    anchore.get_vulns()
    anchore.get_compliance()
    anchore.get_version()



if __name__ == "__main__":
    sys.exit(main())

