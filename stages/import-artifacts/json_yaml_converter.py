#!/usr/bin/python3
import os
import sys
import getopt
import yaml
import json
import logging

# Get logging level, set manually when running pipeline
loglevel = os.environ.get('LOGLEVEL', 'INFO').upper()
if loglevel == 'DEBUG':
    logging.basicConfig(level=loglevel, format="%(levelname)s [%(filename)s:%(lineno)d]: %(message)s")
    logging.debug("Log level set to debug")
else:
    logging.basicConfig(level=loglevel, format="%(levelname)s: %(message)s")
    logging.info("Log level set to info")

inputFile = ""
outputFile = ""
try:
    opts, args = getopt.getopt(sys.argv[1:],"hi:o:",["ifile=","ofile="])
except getopt.GetoptError:
    print('downloader.py -i <inputfile> -o <outputfile>')
    sys.exit(2)
for opt, arg in opts:
    if opt == '-h':
        print('downloader.py -i <inputfile> -o <outputfile>')
        sys.exit()
    elif opt in ("-i", "--ifile"):
        inputFile = arg
    elif opt in ("-o", "--ofile"):
        outputFile = arg

print('Input file:', inputFile)
print('Output file:', outputFile)

download_list = yaml.dump(json.load(open("download.json")))

with open(outputFile, 'w') as f:
    print(download_list)
    f.write(download_list)