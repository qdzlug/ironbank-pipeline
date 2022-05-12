#!/usr/bin/env python3

import argparse
import gitlab
import yaml
import sys
import os
import jinja2
from pyrate_limiter import Duration, Limiter, RequestRate
import requests

# VAT config
vat_api_url = f"{os.environ['VAT_BACKEND_SERVER_ADDRESS']}/p1"

# Set the rate limiters. These have to be global and specified first.
# Modifying these during the main function has no effect, so these
# values ultimately require being hardcoded.
issuelimiter = Limiter(RequestRate(50, Duration.MINUTE))
# Limits the number of issues created (by minute)
pipelinelimiter = Limiter(RequestRate(20, Duration.HOUR))
# Limits the number of pipeline triggers (by hour)
readlimiter = Limiter(RequestRate(720, Duration.MINUTE))
# Limits ALL read API's (by minute)

#################################################
# These functions are grouped into the same 'read-only' rate limiter
# to help reduce/prevent random remote disconnects. This form of
# rate-limiting only applies to the function, not individual API
# calls that may be necessary such as pagination.


@readlimiter.ratelimit("readlimiter", delay=True)
def getProjects(gl, targetGroup):
    for i in range(1, retries + 1):
        try:
            group = gl.groups.get(targetGroup)
        except gitlab.exceptions.GitlabHttpError as e:
            print(e)
        except requests.exceptions.ConnectionError as e:
            print(f"  - [{i}/{retries}] Failed retrieving project due to: {e}")

        if not group:
            break

        try:
            return group.projects.list(
                all=True, as_list=True, include_subgroups=True, archived=False
            )
        except gitlab.exceptions.GitlabHttpError as e:
            print(f"  - [{i}/{retries}] Failed retrieving projects due to: {e}")
        except requests.exceptions.ConnectionError as e:
            print(f"  - [{i}/{retries}] Failed retrieving project due to: {e}")


@readlimiter.ratelimit("readlimiter", delay=True)
def getProject(gl, projectId):

    for i in range(1, retries + 1):
        try:
            return gl.projects.get(projectId)
        except gitlab.exceptions.GitlabHttpError as e:
            print(f"  - [{i}/{retries}] Failed retrieving project due to: {e}")
        except requests.exceptions.ConnectionError as e:
            print(f"  - [{i}/{retries}] Failed retrieving project due to: {e}")


@readlimiter.ratelimit("readlimiter", delay=True)
def getManifest(project):
    parent = ""
    image = ""
    tag = ""

    for i in range(1, retries + 1):
        try:
            manifest = project.files.get(
                file_path="hardening_manifest.yaml", ref="master"
            )
            contents = yaml.load(manifest.decode(), Loader=yaml.FullLoader)

            parent = contents["args"]["BASE_IMAGE"]
            image = contents["name"]
            tag = contents["tags"][0]
        except gitlab.exceptions.GitlabHttpError as e:
            print(
                f"  - [{i}/{retries}] Failed retrieving pipeline job trace due to: {e}"
            )

            parent = ""
            image = ""
            tag = ""
        except requests.exceptions.ConnectionError as e:
            print(f"  - [{i}/{retries}] Failed retrieving project due to: {e}")

            parent = ""
            image = ""
            tag = ""

    return parent, image, tag


#################################################

#################################################


@issuelimiter.ratelimit("issuelimiter", delay=True)
def createBaseImageIssue(project, image):

    # Create the templating objects
    templateLoader = jinja2.FileSystemLoader(searchpath="./templates")
    templateEnv = jinja2.Environment(loader=templateLoader)

    # Load the template
    template = templateEnv.get_template("issue.md")

    # Render the template
    body = template.render(image=image)

    # Create the ticket
    issue = project.issues.create(
        {"title": "Update base image for " + image, "description": body}
    )

    if issue:
        return True
    else:
        return False


#################################################

# Check image against VAT api to validate status is active


def checkVatStatus(image, tag):
    try:
        r = requests.get(f"{vat_api_url}/container?name={image}&tag={tag}")
        r.raise_for_status()

        checkImage = r.json()

        if checkImage["lifecycle"] != "Active":
            return False

        return True
    except requests.exceptions.HTTPError as e:
        print(e)
    except requests.exceptions.RequestException as e:
        print(e)


# Main function


def main(argv):
    # Global variables
    global retries

    parser = argparse.ArgumentParser("notifier")

    parser.add_argument(
        "-u", "--url", default="", help="The URL to the GitLab instance."
    )
    parser.add_argument(
        "-t",
        "--token",
        default="",
        help="The access token to use when querying the GitLab instance.",
    )
    parser.add_argument(
        "-g",
        "--group",
        default="40",
        help="The GitLab group to target and apply templates to all subprojects.",
    )
    parser.add_argument(
        "-i", "--image", default="redhat/ubi/ubi8", help="The base image to detect."
    )
    parser.add_argument(
        "-r",
        "--retries",
        default=3,
        help="Specifies the maximum number of retries for failed API call.",
    )
    args = parser.parse_args()

    # Process command-line arguments
    gitlab_url = args.url
    gitlab_token = args.token
    targetGroup = args.group
    baseImage = args.image
    retries = args.retries

    # Make sure the retries are greater than 0
    if retries < 1:
        print("Retries must have a value greater than 0.")

    gl = gitlab.Gitlab(gitlab_url, private_token=gitlab_token)
    gl.auth()

    # Get a list of all the Gitlab projects. Additionally, to reduce API calls later
    # we just go ahead and do them all now with `as_list=True`.
    print("Getting a list of all projects...")
    projects = getProjects(gl, targetGroup)

    # Initialize array for the tickets and MRs we want to create later
    baseImageIssues = []

    # Loop through each of the projects
    current = 1
    total = len(projects)
    print("Processing projects... ")
    for project in projects:
        # We don't truly have a project object that we can act upon (we have a GroupProject), so
        # we need another API call to get a proper Project object.
        project = getProject(gl, project.id)

        # Indicate to the user how far along we are
        percent = round((current / total) * 100, 1)
        print(f"[{current}/{total} - {percent}%] {project.path_with_namespace}")

        # Get the parent and the image name from the hardening manifest
        parent, image, tag = getManifest(project)

        # only process if the image/tag active in VAT
        if tag and checkVatStatus(image, tag):
            print(f"Processing active image {image}:{tag} with parent {parent}")

            if parent == baseImage:
                baseImageIssues.append({"project": project, "image": image})

        current += 1

    # Print/create the number of issues
    print()
    print(f"Total new base image tickets to create: {len(baseImageIssues)}")
    if baseImageIssues:
        for i in range(0, len(baseImageIssues)):
            print(
                f'[{i+1}/{len(baseImageIssues)} - {(round((i+1)/len(baseImageIssues)*100,1))}%] Creating issue for {baseImageIssues[i]["project"].path_with_namespace}'
            )
            createBaseImageIssue(
                baseImageIssues[i]["project"], baseImageIssues[i]["image"]
            )
        print()


if __name__ == "__main__":
    main(sys.argv[1:])
