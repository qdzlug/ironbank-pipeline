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
    # Use the project ironbank.yaml file path if one exists
    # Use the generated ironbank.yaml file path if not
    inputFile = ""
    try:
      opts, args = getopt.getopt(sys.argv[1:], "hi:", ["ifile="])
    except getopt.GetoptError:
      print("downloader.py -i <inputfile>")
      sys.exit(2)
    for opt, arg in opts:
      if opt in ("-i", "--ifile"):
        inputFile = arg
      if inputFile == "":
        print("No input file specified.")
        sys.exit(1)

    # print("Input file:", inputFile, file=sys.stderr)

    ##### Read ironbank.yaml file
    with open(inputFile, "r") as file:
        content = yaml.safe_load(file)
    
    
    for type in content:
        if type == "path":
          try:
            path_str = content["path"]
            print(f"IMAGE_PATH={path_str}")
          except:
            print("There was an issue with retrieving the image path in ironbank.yaml", file=sys.stderr)

        if type == "tags":
          try:
            tag_list = content["tags"]
            x = 0
            for item in tag_list:
              tag = content["tags"][x]
              print(f"IMG_VERSION_{x}={tag}")
              x = x + 1
          except:
            print("There was an issue sourcing the tag/image version from ironbank.yaml", file=sys.stderr)
        
        if type == "args":
          try:
            args_list = content["args"]
            base_args = yaml.dump(args_list)
            base_args_content = base_args.split("\n")
            for item in base_args_content:
              if len(item) > 0:
                arg_output = retrieve_content(item)
                print(f"{arg_output}")
          except:
            print("There was an issue sourcing the args from ironbank.yaml", file=sys.stderr)

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
            print("There was an issue sourcing the labels from ironbank.yaml", file=sys.stderr)

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

