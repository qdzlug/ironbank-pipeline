#!/usr/bin/python3
import re
import os
import sys
import yaml
import getopt
import hashlib
import urllib.request
import requests
from requests.auth import HTTPBasicAuth
import shutil
from base64 import b64decode

def main():
    ##### Parse commandline arguments
    inputFile = ""
    outputDir = ""
    docker_resource = None
    http_resource = None
    try:
        opts, args = getopt.getopt(sys.argv[1:],"hi:d:",["ifile=","odir="])
    except getopt.GetoptError:
        print('downloader.py -i <inputfile> -d <outputdir>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('downloader.py -i <inputfile> -d <outputdir>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputFile = arg
        elif opt in ("-d", "--odir"):
            outputDir = arg

    if inputFile == '':
        print("No input file specified.")
        sys.exit(1)

    if outputDir == '':
        print("No output directory specified. Defaulting to current directory.")
        outputDir = "."

    print('Input file:', inputFile)
    print('Output directory:', outputDir)

    ##### Read download.yaml file
    with open(inputFile, "r") as file:
        downloads = yaml.load(file, Loader=yaml.FullLoader)

    for type in downloads:
        if type == "resources":
            for item in downloads[type]:
                download_type = resource_type(item["url"])
                if download_type == "http":
                    http_resource = True
                    if "auth" in item:
                        if item["auth"]["type"] == "basic":
                            credential_id = item["auth"]["id"].replace("-","_")
                            password = b64decode(os.getenv("CREDENTIAL_PASSWORD_" + credential_id)).decode("utf-8")
                            username = b64decode(os.getenv("CREDENTIAL_USERNAME_" + credential_id)).decode("utf-8")
                            http_download(item["url"], item["filename"], item["validation"]["type"], item["validation"]["value"], outputDir, username, password)
                        else:
                            print("Non Basic auth type provided for HTTP resource, failing")
                            sys.exit(1)
                    else:
                        http_download(item["url"], item["filename"], item["validation"]["type"], item["validation"]["value"], outputDir)
                if download_type == "docker":
                    docker_resource = True
                    docker_download(item["url"], item["tag"], item["tag"])
                if download_type == "s3":
                    s3_resource = True
            # print()
    # Check if http or docker resources were downloaded and set environment variables for build stage
    if http_resource is not None:
        os.system("echo 'HTTP_RESOURCE=TRUE' >> artifact.env")
    if docker_resource is not None:
        os.system("echo 'DOCKER_RESOURCE=TRUE' >> artifact.env")

def resource_type(url):
    check = url
    docker_string = "docker://"
    http_string = "http"
    s3_string = "s3://"
    if docker_string in check:
        return "docker"
    elif http_string in check:
        return "http"
    elif s3_string in check:
        return "s3"
    else:
        return "Error in parsing resource type."

def http_download(download_item, resource_name, validation_type, checksum_value, outputDir, username=None, password=None):
    print("===== ARTIFACT: %s" % download_item)
    # Validate filename doesn't do anything nefarious
    match = re.search(r'^[A-Za-z0-9]+[A-Za-z0-9_\-\.]*[A-Za-z0-9]+$', resource_name)
    if match is None:
        print("Filename is has invalid characters. Aborting.")
        sys.exit(1)

    else:
        auth = None
        if username and password:
            auth = HTTPBasicAuth(username, password)

        print("Downloading from %s" % download_item)
        with requests.get(download_item, allow_redirects=True, stream=True, auth=auth) as r:
            r.raise_for_status()
            with open(outputDir + "/external-resources/" + resource_name, 'wb') as f:
                shutil.copyfileobj(r.raw, f, length=16*1024*1024)

        # Calculate SHA256 checksum of downloaded file
        print("Checking file verification type")

        if validation_type != "sha256" and validation_type != "sha512":
            print("file verification type not supported: '%s'" % validation_type)
            sys.exit(1)

        print("Generating checksum")
        checksum_value_from_calc = generate_checksum(validation_type, checksum_value, outputDir, resource_name)

        # Compare checksums
        print("comparing checksum values: " + str(checksum_value_from_calc.hexdigest()) + " vs " + str(checksum_value))
        if checksum_value_from_calc.hexdigest() == checksum_value:
            print("Checksum verified")
            print("File saved as '%s'" % resource_name)
        else:
            os.remove(outputDir + "/external-resources/" + resource_name)
            print("Checksum failed")
            print("File deleted")
            sys.exit(1)


def generate_checksum(validation_type, checksum_value, outputDir, resource_name):
    if validation_type == "sha256":
        sha256_hash = hashlib.sha256()
        with open(outputDir + "/external-resources/" + resource_name, "rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
            return sha256_hash
    elif validation_type == "sha512":
            sha512_hash = hashlib.sha512()
            with open(outputDir + "/external-resources/" + resource_name, "rb") as f:
                for byte_block in iter(lambda: f.read(4096),b""):
                    sha512_hash.update(byte_block)
                return sha512_hash


def docker_download(download_item, tag_value, tar_name):
    print("===== ARTIFACT: %s" % download_item)
    image = download_item.split('//')[1]
    tar_name = tar_name.replace('/', '-')
    tar_name = tar_name.replace(':', '-')
    print("Pulling " + image)
    os.system("podman pull " + image)
    print("Tagging image as " + tag_value)
    os.system("podman tag " + image + " " + tag_value)
    print("Saving " + tag_value + " as tar file")
    os.system("podman save -o " + tar_name + ".tar " + tag_value)
    print("Moving tar file into stage artifacts")
    os.system("cp " + tar_name + ".tar ${ARTIFACT_STORAGE}/import-artifacts/images/")

if __name__ == "__main__":
    main()
