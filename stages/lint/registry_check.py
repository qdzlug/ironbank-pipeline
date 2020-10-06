#!/usr/bin/python3
import sys
import argparse
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


parser = argparse.ArgumentParser(description='Ensure proper registry usage in Dockerfiles')
parser.add_argument('--dockerfile-path', help='path to Dockerfile to parse')
args = parser.parse_args()

filepath = args.dockerfile-path
registry_string = "ARG BASE_REGISTRY=registry1.dsop.io/ironbank"
print("\nSearching for " + registry_string + " in file to confirm Registry1 ironbank is being used as the base registry in image build.\n")
with open(filepath) as f:
  if registry_string in f.read():
    print("Base registry found")
  else:
    print("Could not locate " + registry_string + " as the BASE_REGISTRY argument in the Dockerfile.\n")
    print("Please ensure you are using " + registry_string + "for the base registry in your build.\n")
    print("This check is performed to ensure base images are built from approved IronBank images and that Dockerfiles across the IronBank have uniform base registry arguments.")
