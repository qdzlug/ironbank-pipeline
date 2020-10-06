#!/usr/bin/python3
import re
import os
import subprocess
import logging
import sys
import yaml
import getopt
import hashlib
import requests
import boto3
from botocore.exceptions import ClientError
from requests.auth import HTTPBasicAuth
import shutil
from base64 import b64decode
import logging
from distutils import util



def main():
    # Get logging level, set manually when running pipeline
    debug = bool(util.strtobool(os.getenv("DEBUG", default = False)))
    if debug is True:
        logging.basicConfig(level = logging.DEBUG, format = "%(levelname)s [%(filename)s:%(lineno)d]: %(message)s")
        logging.info("Set the log level to debug")
    else:
        logging.basicConfig(level = logging.INFO, format = "%(levelname)s: %(message)s")
        logging.info("Set the log level to info")

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
                    if "auth" in item:
                        if item["auth"]["type"] == "basic":
                            credential_id = item["auth"]["id"].replace("-","_")
                            password = b64decode(os.getenv("CREDENTIAL_PASSWORD_" + credential_id))
                            username = b64decode(os.getenv("CREDENTIAL_USERNAME_" + credential_id))
                            http_download(item["url"], item["filename"], item["validation"]["type"], item["validation"]["value"], outputDir, username, password)
                        else:
                            print("Non Basic auth type provided for HTTP resource, failing")
                            sys.exit(1)
                    else:
                        http_download(item["url"], item["filename"], item["validation"]["type"], item["validation"]["value"], outputDir)
                if download_type == "docker":
                    docker_download(item["url"], item["tag"], item["tag"])
                if download_type == "s3":
                    if "auth" in item:
                        credential_id = item["auth"]["id"].replace("-","_")
                        username = b64decode(os.getenv("S3_ACCESS_KEY_" + credential_id)).decode('utf-8')
                        password = b64decode(os.getenv("S3_SECRET_KEY_" + credential_id)).decode('utf-8')
                        region = item["auth"]["region"]
                        s3_download(item["url"], item["filename"], item["validation"]["type"], item["validation"]["value"], outputDir, username, password, region)
                    else:
                        s3_download(item["url"], item["filename"], item["validation"]["type"], item["validation"]["value"], outputDir)

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
    match = re.search(r'^[A-Za-z0-9][^/\x00]*', resource_name)
    if match is None:
        print("Filename is has invalid characters. Filename must start with a letter or a number. Aborting.")
        sys.exit(1)

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

def s3_download(download_item, resource_name, validation_type, checksum_value, outputDir, username=None, password=None, region=None):
    print("===== ARTIFACT: %s" % download_item)
    
    bucket = download_item.split('s3://')[1].split('/')[0]
    object_name = download_item[len('s3://' + bucket + '/'):]
    # Validate filename doesn't do anything nefarious
    match = re.search(r'^[A-Za-z0-9][^/\x00]*', resource_name)
    if match is None:
        print("Filename is has invalid characters. Filename must start with a letter or a number. Aborting.")
        sys.exit(1)
   
    s3_client = boto3.client('s3',
                         aws_access_key_id=username,
                         aws_secret_access_key=password,
                         region_name=region
                      )

    try:
        response = s3_client.download_file(bucket, object_name, outputDir + "/external-resources/" + resource_name)
    except ClientError as e:
        logging.error(e)
        return False
    
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

    retry_count = 0
    while True:
        try:
            subprocess.run(["podman", "pull", image], check=True)
            print("Tagging image as " + tag_value)
            subprocess.run(["podman", "tag", image, tag_value], check=True)
            print("Saving " + tag_value + " as tar file")
            subprocess.run(["podman", "save",  "-o", tar_name + ".tar", tag_value], check=True)
            print("Moving tar file into stage artifacts")
            shutil.copy(tar_name + ".tar", os.getenv("ARTIFACT_STORAGE") + "/import-artifacts/images/")
        except subprocess.CalledProcessError as e:
            if  retry_count > 1:
                print("Docker resource failed to pull, please check download.yaml configuration")
                sys.exit(1)
            else:
                print("Docker resource failed to pull, retrying: " + retry_count + "/3")
                retry_count += 1
        break

if __name__ == "__main__":
    main()
