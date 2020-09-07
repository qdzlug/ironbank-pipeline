import re
import os
import sys
import yaml
import getopt
import hashlib
import urllib.request


def main():
    ##### Parse commandline arguments
    inputFile = ""
    outputDir = ""
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
                    resource_name = item["filename"]
                    validation_type = item["validation"]["type"]
                    checksum_value = item["validation"]["value"]
                    http_download(item["url"], item["filename"], item["validation"]["type"], item["validation"]["value"], outputDir)
                if download_type == "docker":
                    tag_value = item["tag"]
                    docker_download(item["url"], item["tag"], item["tag"])
            # print()  

def resource_type(url):
    check = url
    docker_string = "docker://"
    http_string = "http"
    if docker_string in check:
        return "docker"
    elif http_string in check:
        return "http"
    else:
        return "Error in parsing resource type."    

def http_download(download_item, resource_name, validation_type, checksum_value, outputDir):
    print("===== ARTIFACT: %s" % download_item)

    # Validate filename doesn't do anything nefarious
    match = re.search(r'^[A-Za-z0-9]+[A-Za-z0-9_\-\.]*[A-Za-z0-9]+$', resource_name)
    if match is None:
        print("Filename is has invalid characters. Aborting.")
        sys.exit(1)

    else:
        print("Downloading from %s" % download_item)
        urllib.request.urlretrieve(download_item, outputDir + '/' + resource_name)

        # Calculate SHA256 checksum of downloaded file
        print("Generating checksum")

        if validation_type != "sha256":
            print("file verification type not supported: '%s'" % validation_type)
            sys.exit(1)

        sha256_hash = hashlib.sha256()
        with open(outputDir + '/' + resource_name, "rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)

        # Compare SHA256 checksums
        if checksum_value == sha256_hash.hexdigest():
            print("Checksum verified")
            print("File saved as '%s'" % resource_name)
        else:
            os.remove(resource_name)
            print("Checksum failed")
            print("File deleted")

def docker_download(download_item, tag_value, value_for_tar_name):
    print("===== ARTIFACT: %s" % download_item)
    image = download_item.split('//')[1]
    tar_name = value_for_tar_name.split(':')[-1]
    print("Pulling " + image)
    os.system("podman pull " + image)
    print("Tagging image as " + tag_value)
    os.system("podman tag " + image + " " + tag_value)
    os.system("echo 'DOCKER_RESOURCE=TRUE' >> artifact.env")
    print("Saving " + tag_value + " as tar file")
    os.system("podman save -o " + tar_name + ".tar " + tag_value)
    print("Moving tar file into stage artifacts")
    os.system("cp " + tar_name + ".tar ${ARTIFACT_STORAGE}/import-artifacts/images/")

if __name__ == "__main__":  
    main()
