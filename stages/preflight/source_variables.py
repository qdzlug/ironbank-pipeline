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
    # Use the temp ironbank.yaml file path if not
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

    print("Input file:", inputFile)

    ##### Read ironbank.yaml file
    with open(inputFile, "r") as file:
        content = yaml.safe_load(file)
      
    # for type in content:
    #   if type == "name":
    #     for item in content.items():
    #       test = item["name"]
    #       print(test)
          # name_content = item["name"]
          # subprocess.call(["echo", name_content])
          # print(item, ":")
    
    for type in content:
        if type == "name":
          name_path = content["name"]
          # subprocess.call(["echo", name_path])
          print(name_path)
        if type == "tags":
          tag_list = content["tags"]
          x = 0
          for index in tag_list:
            tag = content["tags"][x]
            # subprocess.call(["echo", tag])
            print(tag)
            x = x + 1
        if type == "args":
          args_list = content["args"]
          base_args = yaml.dump(args_list)
          # subprocess.call(["echo", base_args])
          print(base_args)
        if type == "labels":
          labels_list = content["labels"]
          container_labels = yaml.dump(labels_list)
          # subprocess.call(["echo", container_labels])
          print(container_labels)
        # I have left out "resources"
        # "resources" are covered in the downloader.py script in import artifacts
        if type == "maintainers":
          maintainers_list = content["maintainers"]
          maintainers_section = yaml.dump(maintainers_list)
          # subprocess.call(["echo", maintainers_section])
          print(maintainers_section)
  

if __name__ == "__main__":
    main()

