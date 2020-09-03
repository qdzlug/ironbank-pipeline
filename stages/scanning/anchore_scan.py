#!/usr/bin/python3
import argparse
import re
import requests
import json
import csv
import subprocess

# Hopefully this is there
# TODO: Import only needed components
import os

#
## Creates JSON reports for all image vulnerabilities
# support both python2 and python3 url encoding modules
#
try:
    from urllib.parse import quote_plus,unquote_plus, quote, unquote
except:
    from urllib import quote_plus,unquote_plus, quote, unquote

#
# Get the arguments
#
parser = argparse.ArgumentParser(description="Anchore Image Vuln Report Generator")
parser.add_argument('--u', metavar='user', default='admin', help='Anchore admin username (default=admin)')
parser.add_argument('--p', metavar='pass', default='foobar', help='Anchore admin password (default=foobar)')
parser.add_argument('--url', metavar='url', default='http://localhost:8228/v1/', help='Anchore Engine API Service endpoint URL (default=http://localhost:8228/v1/)')
parser.add_argument('--verify', metavar='verify', default=True, help='Accept self-signed certificates when using TLS/https for anchore endpoint')
parser.add_argument('--image', metavar='image', default='none', help='Full image tag to get vulnerability info. ex. docker.io/library/alpine:latest')
parser.add_argument('--output', metavar='output', default='.', help='Output directory for reports.')

args = parser.parse_args()
endpoint_url = re.sub("\/+$", '', args.url)


#
# Get image digest
#
def getImageDigest():
    request_url = f"{endpoint_url}/images"
    payload = {'fulltag': args.image, 'history': 'false'}

    try:
        r = requests.get(
                request_url,
                auth=(args.u, args.p),
                params=payload,
                verify=args.verify
        )
        body = r.text

        if r.status_code == 200:
            # test that the response is valid JSON
            try:
                image_list = json.loads(body)
                image_digest = image_list[0]["imageDigest"]
                print("Anchore Image Digest = " + image_digest)
                if image_digest == None:
                    raise Exception("Image Digest does not Exist")
                return image_digest
            except:
                raise Exception("Got 200 response but is not valid JSON")
        else:
            raise Exception("Non-200 response recieved from Anchore " + str(r.status_code) + " - " + r.text)

    except Exception as err:
        raise err


#
# Get vulnerabilities for image
#
def get_vulndb(report_dir, digest):
    request_url = f"{endpoint_url}/images/{digest}/vuln/all"

    try:
        r = requests.get(
                request_url,
                auth=(args.u, args.p),
                verify=args.verify
        )
        body = r.text

        if r.status_code == 200:
            # test that the response is valid json
            try:
                vuln_dict = json.loads(body)
                for vulnerability in vuln_dict['vulnerabilities']:
                    # If VulnDB record found, retrive set of reference URLs associated with the record.
                    if (vulnerability["feed_group"] == "vulndb:vulnerabilities"):
                        # "http://anchore-anchore-engine-api:8228/v1" or URL to replace may need to be modified when changes to the Anchore installation occur
                        vulndb_request_url = re.sub("http:\/\/([a-z-_0-9:]*)\/v1", endpoint_url, vulnerability["url"])
                        r = requests.get(vulndb_request_url, auth=(args.u, args.p))
                        body = r.text

                        if r.status_code == 200:
                        # test that the response is valid json
                            try:
                                vulndb_dict = json.loads(body)
                                for vulndb_vuln in vulndb_dict["vulnerabilities"]:
                                    vulnerability['url'] = vulndb_vuln["references"]

                            except:
                                raise Exception("Got 200 response, but data isn't valid JSON")
                vuln_dict["imageFullTag"] = args.image
                # Create json report called anchore_vulns_new.json
                try:
                    with open('anchore_security.json', 'w') as fp:
                        json.dump(vuln_dict, fp)

                    with open(os.path.join(report_dir, 'anchore_security.json'), 'w') as fp:
                        json.dump(vuln_dict, fp)

                except Exception as err:
                    raise err

            except:
                raise Exception("Got 200 response, but data isn't valid JSON")

    except Exception as err:
        # if any report fails, raise the error and failstop program
        raise err


def get_gates(report_dir, digest):

    request_url = f"{endpoint_url}/images/{digest}/check?tag={args.image}&detail=true"

    try:
        r = requests.get(
                request_url,
                auth = (args.u, args.p),
                verify = args.verify
        )
        body = r.text
        if r.status_code == 200:
            try:
                body_json = json.loads(body)

                # Save the API response
                # with open("anchoreengine-api-response-evaluation-1.json", "w") as f:
                #     f.write(body)

                imageid = body_json[0][digest]["docker.io/" + args.image][0]["detail"]["result"]["image_id"]
                results = body_json[0][digest]["docker.io/" + args.image][0]["detail"]["result"]["result"]

                results_dict = dict()

                # Grab the subset of data used in anchore_gates.json
                results_dict[imageid] = results[imageid]

                with open(os.path.join(report_dir, "anchore_gates.json"), "w") as f:
                    json.dump(results_dict, f)

            except Exception as err:
                raise err
        else:
            raise Exception("Non-200 response recieved from Anchore " + str(r.status_code) + " - " + r.text)

    except Exception as err:
        raise err


#
#
#
def get_security(report_dir, digest):

    request_url = f"{endpoint_url}/images/{digest}/vuln/all"

    try:
        r = requests.get(
                request_url,
                auth = (args.u, args.p),
                verify = args.verify
        )
        body = r.text
        if r.status_code == 200:
            try:
                body_json = json.loads(body)
                print(body_json)

                results_dict = {
                        "columns": [
                            { "title": "Tag" },
                            { "title": "CVE ID" },
                            { "title": "Severity" },
                            { "title": "Vulnerability Package" },
                            { "title": "Fix Available" },
                            { "title": "URL" }
                        ],
                        "data": [ ]
                    }

                vulns = body_json["vulnerabilities"]

                for i in range(len(vulns)):
                    try:
                        results_dict["data"].append([
                            args.image,
                            vulns[i]["vuln"],
                            vulns[i]["severity"],
                            vulns[i]["package"],
                            vulns[i]["fix"],
                            vulns[i]["url"]
                        ])
                    except Exception as err:
                        raise err

                with open(os.path.join(report_dir, "anchore_security.json"), "w") as f:
                    json.dump(results_dict, f)

            except Exception as err:
                raise err
        else:
            raise Exception("Non-200 response recieved from Anchore " + str(r.status_code) + " - " + r.text)

    except Exception as err:
        raise err


#
#
#
def get_version(report_dir):

    request_url = f"{endpoint_url}/version"

    try:
        r = requests.get(
                request_url,
                auth = (args.u, args.p),
                verify = args.verify
        )
        body = r.text
        if r.status_code == 200:
            try:
                body_json = json.loads(body)

                with open("anchore-version.txt", "w") as f:
                    json.dump(body_json["service"]["version"], f)

                with open(os.path.join(report_dir, "anchore-version.txt"), "w") as f:
                    json.dump(body_json["service"]["version"], f)

            except Exception as err:
                raise err
        else:
            raise Exception("Non-200 response recieved from Anchore " + str(r.status_code) + " - " + r.text)

    except Exception as err:
        raise err


#
# Generat the reports (entrypoint)
#
def generate_reports():
    # Need to grab BRANCH_NAME and BUILD_NUMBER
    branch_name  = os.getenv("BRANCH_NAME",  default = "branchname")
    build_number = os.getenv("BUILD_NUMBER", default = "buildnumber")

    report_dir = args.output #os.path.join(args.output, f"AnchoreReport.{branch_name}_{build_number}_DEV")

    if not os.path.exists(report_dir):
        os.makedirs(report_dir, 0o755)

    print(f"Created Anchore Report Directory: {report_dir}")

    p = subprocess.Popen(["anchore-cli", "image", "add", args.image],
            stdout = subprocess.PIPE,
            stderr = subprocess.STDOUT)
    stdout, stderr = p.communicate()
    print(stdout)
    print(stderr)

    p = subprocess.Popen(["anchore-cli", "image", "wait", args.image],
            stdout = subprocess.PIPE,
            stderr = subprocess.STDOUT)
    stdout, stderr = p.communicate()
    print(stdout)
    print(stderr)

    digest = getImageDigest()

    get_gates    (report_dir = report_dir, digest = digest)
    get_vulndb   (report_dir = report_dir, digest = digest)
    get_version  (report_dir = report_dir)

#
# Entrypoint
#
generate_reports()
