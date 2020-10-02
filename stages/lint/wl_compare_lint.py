#!/usr/bin/python3
import gitlab
import sys
import os
import json
import argparse

gitlab_url = "https://repo1.dsop.io"
dccscr_project_id = 143

def main():
  parser = argparse.ArgumentParser(description='Lint Whitelist')
  parser.add_argument('--image', help='')
  parser.add_argument('--tag',   help='')
  parser.add_argument('--glkey', help='')
  parser.add_argument('--wlbranch', help='')
  args = parser.parse_args()

  im_name = args.image
  im_tag = args.tag
  gitlab_key = args.glkey
  wl_branch = args.wlbranch

  im_name = '/'.join(im_name.split('/')[1::])

  # Make sure image name follows convention of depth of three directories e.g. 'redhat/ubi/ubi8'
  # If not, throw error
  # check_image_name_length(im_name)
  # get dccscr project object from GitLab
  proj = init(dccscr_project_id, gitlab_key)
  # check if image name/tag match whitelist values
  does_image_exist(proj, im_name, im_tag, wl_branch)
  # Check that image name/tag match provided project values, and all parent images
  get_complete_whitelist_for_image(proj, im_name, im_tag, wl_branch)

# def check_image_name_length(image_name):
#   if not len(image_name.split('/')) == 3:
#     print("Repo name error. Project should be nested three directories deep. e.g. 'redhat/ubi/ubi8'\nCurrent repo name: " + image_name, file=sys.stderr)
#     sys.exit(1)
#   return

def does_image_exist(proj, im_name, im_tag, wl_branch):
  filename = get_whitelist_filename(im_name, im_tag)
  wl = get_whitelist_file_contents(proj, filename, wl_branch)
  if wl['image_name'] != im_name or wl['image_tag'] != im_tag:
    print("Whitelist retrieval error. Check that the project's GitLab reponame matches the whitelist's image name and that the version in the Jenkinsfile matches the whitelist's image tag.\nRepo name and Jenkinsfile version: " + im_name + ":" + im_tag + "\nWhitelist image_name and image_tag: " + wl['image_name'] + ":" + wl['image_tag'], file=sys.stderr)
    sys.exit(1)
  return

def get_complete_whitelist_for_image(proj, im_name, im_tag, wl_branch, child_image_depth=0):
  filename = get_whitelist_filename(im_name, im_tag)
  contents = get_whitelist_file_contents(proj, filename, wl_branch)

  par_image = contents['image_parent_name']
  par_tag = contents['image_parent_tag']

  if contents['image_name'] == im_name and contents['image_tag'] == im_tag:
    if len(par_image) > 0 and len(par_tag) > 0:
      print("Fetching Whitelisted CVEs from parent: " + par_image + ':' + par_tag, file=sys.stderr)
      get_complete_whitelist_for_image(proj, par_image, par_tag, wl_branch, child_image_depth=child_image_depth+1)
      # Only output IMAGE_APPROVAL_STATUS on the child image (not for parent images)
      if child_image_depth == 0:
        print(f"IMAGE_APPROVAL_STATUS={contents['approval_status']}")
        print(f"BASE_IMAGE={contents['image_parent_name']}") # empty string for base image
        print(f"BASE_TAG={contents['image_parent_tag']}") # empty string for base image
        # BASE_REGISTRY is a constant value
        print(f"BASE_REGISTRY=${os.environ['REGISTRY_URL']}")
      else:
        if contents['approval_status'] != 'approved':
          print(f"WARNING: unapproved parent image: {contents['image_name']}:{contents['image_tag']}", file=sys.stderr)
    # Output IMAGE_APPROVAL_STATUS for base images like UBI
    elif child_image_depth == 0:
      print(f"IMAGE_APPROVAL_STATUS={contents['approval_status']}")
      print(f"BASE_REGISTRY=${os.environ['REGISTRY_URL']}")
  else:
    print("Mismatched image name/tag in " + filename + "\nRetrieved Image Name: " + contents['image_name'] + ":" + contents['image_tag'] + "\nSupplied Image Name: " + im_name + ":" + im_tag + "\nCheck parent image tag in your whitelist file.", file=sys.stderr)
    sys.exit(1)

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

def init(pid, gitlab_key):
  gl = gitlab.Gitlab(gitlab_url, private_token=gitlab_key)
  return gl.projects.get(pid)

if __name__ == "__main__":
  main()
