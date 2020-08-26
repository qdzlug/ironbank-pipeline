import re
import os
import sys
import yaml
import getopt
import hashlib
import urllib.request

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
    if type == "artifacts":
        for item in downloads[type]:
            print("===== ARTIFACT: %s" % (item["name"]))

            # Validate filename doesn't do anything nefarious
            # ENSURE Dockerfile is not clobbered by the following regex
            match = re.search(r'^[A-Za-z0-9]+[A-Za-z0-9_\-\.]*[A-Za-z0-9]+$', item["filename"])
            if match is None:
                print("Filename is has invalid characters. Aborting.")
                sys.exit(1)

            # Validate username and password exist (if provided)
            if item["username"] is not None:
                if item["username"] not in os.environ.keys():
                    print("Environment variable '%s' does not exist. Aborting." % (item["username"]))
                    sys.exit(2)
            if item["password"] is not None:
                if item["password"] not in os.environ.keys():
                    print("Environment variable '%s' does not exist. Aborting." % (item["password"]))
                    sys.exit(2)

            # If username and password is specified, we should download using those credentials
            if item["username"] is not None and item["password"] is not None:
                print("Downloading from %s using HTTP basic authentication" % (item["url"]))
                
                # Create a password manager and add the tokens
                password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                password_mgr.add_password(None, item["url"], item["username"], item["password"])
                handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
                opener = urllib.request.build_opener(handler)
                opener.open(item["url"])

                # Download the file
                response = urllib.request.urlopen(item["url"])

                # Write downloaded file to specified filename
                f = open(outputDir + '/' + item["filename"], "wb")
                f.write(response.read())
                f.close()
            else:
                print("Downloading from %s" % (item["url"]))
                urllib.request.urlretrieve(item["url"], outputDir + '/' + item["filename"])

            # Calculate SHA256 checksum of downloaded file
            print("Generating checksum")

            sha256_hash = hashlib.sha256()
            with open(outputDir + '/' + item["filename"], "rb") as f:
                for byte_block in iter(lambda: f.read(4096),b""):
                    sha256_hash.update(byte_block)

            # Compare SHA256 checksums
            if item["sha256"] == sha256_hash.hexdigest():
                print("Checksum verified")
                print("File saved as '%s'" % (item["filename"]))
            else:
                os.remove(item["filename"])
                print("Checksum failed")
                print("File deleted")
        print()
