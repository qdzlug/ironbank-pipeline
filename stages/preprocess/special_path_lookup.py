#!/usr/bin/env python3
import os.path
import re
import sys
import argparse
import yaml
import json
import logging

def parse_special_path():

    if os.path.isfile("download.yaml"):
        logging.info("download.yaml exists, attempting to extract special image path")
        with open("download.yaml", "r") as yf:
            try:
                data = yaml.load(yf, Loader=yaml.FullLoader)
                special_path = data["special-image-path"]
                logging.info(f"Discovered special path: {special_path}")
                return special_path
            except Exception as e:
                logging.info("Special path not found in download.yaml and will not be used")
    else:
        logging.info("Not found: download.yaml")

    if os.path.isfile("download.json"):
        logging.info("download.json exists, attempting to extract special image path")
        with open("download.json", "r") as jf:
            try:
                data = json.load(jf)
                special_path = data["special-image-path"]
                logging.info(f"Discovered special path: {special_path}")
                return special_path
            except Exception as e:
                logging.info("Special path not found in download.json and will not be used")
    else:
        logging.info("Not found: download.json")

    return None


def main():
    parser = argparse.ArgumentParser(description = "Special image path parser arguments")
    parser.add_argument("--output",
                        metavar = "output",
                        type = str,
                        help = "Output file from version.py output")
    args = parser.parse_args()
    special_path = parse_special_path()

    if special_path is None:
        logging.error("It does not appear that a special image path was specified. Using default image path value.")
        # return 1
    else:
        with open(args.output, "a") as artifact:
            artifact.write(f"SPECIAL_IMAGE_PATH={special_path}")
        return 0



if __name__ == "__main__":
    sys.exit(main())