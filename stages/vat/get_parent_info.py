#!/usr/bin/python3
import gitlab
import sys
import os
import json
import argparse
import logging
from distutils import util


gitlab_url = "https://repo1.dsop.io" 
dccscr_project_id = 143   

def main():
    # Get logging level, set manually when running pipeline
    debug = bool(util.strtobool(os.getenv("DEBUG", default = False)))
    if debug is True:
        logging.basicConfig(level = logging.DEBUG, format = "%(levelname)s [%(filename)s:%(lineno)d]: %(message)s")
        logging.info("Set the log level to debug")
    else:
        logging.basicConfig(level = logging.INFO, format = "%(levelname)s: %(message)s")
        logging.info("Set the log level to info")
    parser = argparse.ArgumentParser(description='Parent Envs')
    parser.add_argument('--image', help='')
    parser.add_argument('--tag', help='')
    parser.add_argument('--glkey', help='')
    parser.add_argument('--wlbranch', help='')
    parser.add_argument('--output', help='')
    args = parser.parse_args()

    im_name = args.image
    im_tag = args.tag
    gitlab_key = args.glkey
    wl_branch = args.wlbranch
    output = args.output

    im_name = '/'.join(im_name.split('/')[1::])
    # get dccscr project object from GitLab
    proj = init(dccscr_project_id, gitlab_key)
    
    get_parent_info(proj, im_name, im_tag, wl_branch, output)

def get_whitelist_filename(im_name, im_tag):
  dccscr_project = im_name.split('/')
  greylist_name = dccscr_project[-1] + '.greylist'
  dccscr_project.append(greylist_name)
  filename = '/'.join(dccscr_project)
  return filename

def get_whitelist_file_contents(proj, item_path, item_ref):
  try:
    wl_file = proj.files.get(file_path=item_path, ref=item_ref)
  except:
    print("Error retrieving whitelist file:", sys.exc_info()[1], file=sys.stderr)
    print("Whitelist retrieval attempted: " + item_path, file=sys.stderr)
    sys.exit(1)
  try:
    contents = json.loads(wl_file.decode())
  except ValueError as error:
    print("JSON object issue: %s", file=sys.stderr) % error
    sys.exit(1)
  return contents

#create file to set environment variables for PARENT_NAME and PARENT_TAG
def get_parent_info(proj, im_name, im_tag, wl_branch, output):
    filename = get_whitelist_filename(im_name, im_tag)
    contents = get_whitelist_file_contents(proj, filename, wl_branch)

    par_image = contents['image_parent_name']
    par_tag = contents['image_parent_tag']

    with open(output, 'w') as environment:
        environment.write(f"export PARENT_NAME={par_image}\n")
        environment.write(f"export PARENT_TAG={par_tag}")

def init(pid, gitlab_key):
  gl = gitlab.Gitlab(gitlab_url, private_token=gitlab_key)
  return gl.projects.get(pid)

if __name__ == "__main__":
    main()
