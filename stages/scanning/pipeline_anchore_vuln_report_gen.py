#!/usr/bin/python3
import argparse
import re
import requests
import json
import csv

## Creates JSON reports for all image vulnerabilities
# support both python2 and python3 url encoding modules
try:
    from urllib.parse import quote_plus,unquote_plus, quote, unquote
except:
    from urllib import quote_plus,unquote_plus, quote, unquote

parser = argparse.ArgumentParser(description="Anchore Image Vuln Report Generator")
parser.add_argument('--u', metavar='user', default='admin', help='Anchore admin username (default=admin)')
parser.add_argument('--p', metavar='pass', default='foobar', help='Anchore admin password (default=foobar)')
parser.add_argument('--url', metavar='url', default='http://localhost:8228/v1/', help='Anchore Engine API Service endpoint URL (default=http://localhost:8228/v1/)')
parser.add_argument('--verify', metavar='verify', default=True, help='Accept self-signed certificates when using TLS/https for anchore endpoint')
parser.add_argument('--image', metavar='image', default='none', help='Full image tag to get vulnerability info. ex. docker.io/library/alpine:latest')

args = parser.parse_args()
endpoint_url = re.sub("\/+$", '', args.url)

# Get image digest
def getImageDigest(): 
    image_query = "/images"
    digest_request_url = endpoint_url + image_query
    payload = {'fulltag': args.image, 'history': 'false'}

    try:
        r = requests.get(digest_request_url, auth=(args.u, args.p), params=payload, verify=args.verify)
        response_body = r.text

        if r.status_code == 200:
            # test that the response is valid JSON
            try:
                image_list = json.loads(response_body)
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

# Get vulnerabilities for image
def getImageVulns():   
    image_digest = getImageDigest()
    query_url = "/images/" + image_digest + "/vuln/all"
    request_url = endpoint_url + query_url

    try:
        r = requests.get(request_url, auth=(args.u, args.p), verify=args.verify)
        response_body = r.text

        if r.status_code == 200:
            # test that the response is valid json
            try:
                vuln_dict = json.loads(response_body)
                #print(vuln_dict)
                for vulnerability in vuln_dict['vulnerabilities']:
                    # If VulnDB record found, retrive set of reference URLs associated with the record.
                    if (vulnerability["feed_group"] == "vulndb:vulnerabilities"):
                        # "http://anchore-anchore-engine-api:8228/v1" or URL to replace may need to be modified when changes to the Anchore installation occur
                        vulndb_request_url = re.sub("http:\/\/([a-z-_0-9:]*)\/v1",endpoint_url,vulnerability["url"])
                        r = requests.get(vulndb_request_url, auth=(args.u, args.p))
                        response_body = r.text

                        if r.status_code == 200:
                        # test that the response is valid json
                            try:
                                vulndb_dict = json.loads(response_body)
                                for vulndb_vuln in vulndb_dict["vulnerabilities"]:
                                    vulnerability['url'] = vulndb_vuln["references"] 
                            
                            except:
                                raise Exception("Got 200 response, but data isn't valid JSON")
                vuln_dict["imageFullTag"] = args.image
                return vuln_dict

            except:
                raise Exception("Got 200 response, but data isn't valid JSON")

    except Exception as err:
        # if any report fails, raise the error and failstop program
        raise err

def generateReports():
    vuln_dict = getImageVulns()
    # Create json report called anchore_vulns_new.json
    try:
        with open('anchore_vulns_new.json', 'w') as fp:
            json.dump(vuln_dict, fp)
    
    except Exception as err:
        raise err

generateReports()
