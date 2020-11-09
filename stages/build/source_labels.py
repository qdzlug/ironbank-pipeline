#!/usr/bin/python3
import logging
import sys
import os
import getopt
import yaml
import subprocess
import re
import sys

def main():
    # Get logging level, set manually when running pipeline
    loglevel = os.environ.get("LOGLEVEL", "INFO").upper()
    if loglevel == "DEBUG":
        logging.basicConfig(
            level=loglevel,
            format="%(levelname)s [%(filename)s:%(lineno)d]: %(message)s",
        )
        logging.debug("Log level set to debug")
    else:
        logging.basicConfig(level=loglevel, format="%(levelname)s: %(message)s")
        logging.info("Log level set to info")

    ##### Parse commandline arguments
    # Use the project description.yaml file path if one exists
    # Use the generated description.yaml file path if not
    inputFile = ""
    try:
      opts, args = getopt.getopt(sys.argv[1:], "hi:", ["ifile="])
    except getopt.GetoptError:
      print("parse_labels.py -i <inputfile>")
      sys.exit(2)
    for opt, arg in opts:
      if opt in ("-i", "--ifile"):
        inputFile = arg
      if inputFile == "":
        print("No input file specified.")
        sys.exit(1)

    print("Input file:", inputFile, file=sys.stderr)

    ##### Read description.yaml file
    with open(inputFile, "r") as file:
        content = yaml.safe_load(file)
    
        if type == "labels":
          try:
            labels_list = content["labels"]
            labels_content = yaml.dump(labels_list)
            labels = labels_content.split("\n")
            for item in labels:
              if len(item) > 0:
                label_output = retrieve_content(item)
                print(f"{label_output}")
          except:
            print("There was an issue sourcing the labels from description.yaml", file=sys.stderr)

        # "resources" intentionally left out
        # "resources" are covered in the downloader.py script in import artifacts
        
        # Maintainers field is used for POC information and won't be parsed

def retrieve_content(yaml_content):
  build_string = ""

  build_string += yaml_content

  output_string = build_string.replace(": ", "=")

  return output_string

if __name__ == "__main__":
    main()

