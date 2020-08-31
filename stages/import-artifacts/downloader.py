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
    if type == "resources":
        for item in downloads[type]:
            print("===== ARTIFACT: %s" % (item["filename"]))

            # Validate filename doesn't do anything nefarious
            match = re.search(r'^[A-Za-z0-9]+[A-Za-z0-9_\-\.]*[A-Za-z0-9]+$', item["filename"])
            if match is None:
                print("Filename is has invalid characters. Aborting.")
                sys.exit(1)

            else:
                print("Downloading from %s" % (item["url"]))
                urllib.request.urlretrieve(item["url"], outputDir + '/' + item["filename"])

            # Calculate SHA256 checksum of downloaded file
            print("Generating checksum")

            if item["type"] != "sha256":
                print("file verification type not supported: %s", % (item["type"]))
                sys.exit(1)

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
