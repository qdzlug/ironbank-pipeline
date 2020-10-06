#!/usr/bin/python3
import os
import sys
import getopt
import yaml
import json
import logging
from distutils import util

# Get logging level, set manually when running pipeline
debug = bool(util.strtobool(os.getenv("DEBUG", default = False)))
if debug is True:
    logging.basicConfig(level = logging.DEBUG, format = "%(levelname)s [%(filename)s:%(lineno)d]: %(message)s")
    logging.info("Set the log level to debug")
else:
    logging.basicConfig(level = logging.INFO, format = "%(levelname)s: %(message)s")
    logging.info("Set the log level to info")

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