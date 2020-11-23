#!/usr/bin/env python3

##
#
#   Utilizes the following environment variable
#   - LOGLEVEL
#   - ARTIFACT_STORAGE
#   - WL_TARGET_BRANCH
#   - DISTROLESS
#
##

import re
import os
import sys
import json
import yaml
import gitlab
import pathlib
import logging
import argparse

from bs4 import BeautifulSoup


gitlab_url = "https://repo1.dsop.io"
dccscr_project_id = 143


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

    #
    # Hardening manifest is expected for all of the current repos that are being processed.
    # At the very lease the hardening_manifest.yaml should be generated if it has not been
    # merged in yet. Fetching the parent greylists must be backwards compatible.
    #
    hardening_manifest = load_local_hardening_manifest()
    if hardening_manifest is None:
        logging.error("Your project must contain a hardening_manifest.yaml")
        sys.exit(1)

    image = hardening_manifest["name"]

    x = pipeline_whitelist_compare(image_name=image)

    sys.exit(x)


def load_local_hardening_manifest():
    """
    Load up the hardening_manifest.yaml file as a dictionary. Search for the file in
    the immediate repo first, if that is not found then search for the generated file.

    If neither are found then return None and let the calling function handle the error.

    """
    artifacts_path = os.environ["ARTIFACT_STORAGE"]
    paths = [
        "hardening_manifest.yaml",
        # Check for the generated hardening manifest. This method will be deprecated.
        os.path.join(artifacts_path, "preflight", "hardening_manifest.yaml"),
    ]

    for path in paths:
        logging.info(f"Looking for {path}")
        if pathlib.Path(path).is_file():
            logging.info(f"Using {path}")
            with open(path, "r") as f:
                return yaml.safe_load(f)
        else:
            logging.info(f"Couldn't find {path}")
    return None


def load_remote_hardening_manifest(project, wl_branch="master"):
    if project == "":
        return None

    logging.info(f"Attempting to load hardening_manifest from {project}")

    gl = gitlab.Gitlab(gitlab_url)
    proj = gl.projects.get(f"dsop/{project}")
    logging.info(f"Connecting to dsop/{project}")

    try:
        hardening_manifest = proj.files.get(file_path="hardening_manifest.yaml", ref=wl_branch)
        return hardening_manifest
    except gitlab.exceptions.GitlabError:
        logging.info(
            "Could not load hardening_manifest. Defaulting backwards compatibility."
        )
        logging.warning(
            f"This method will be deprecated soon, please switch {project} to hardening_manifest.yaml"
        )
    return None


def pipeline_whitelist_compare(image_name):

    wl_branch = os.getenv("WL_TARGET_BRANCH", default="master")

    image_whitelist = get_complete_whitelist_for_image(image_name, wl_branch)

    wl_set = set()
    for image in image_whitelist:
        if image.status == "approved":
            wl_set.add(image.vulnerability)

    # Don't go any further if just linting
    if bool(os.getenv("LINT", default=False)):
        return 0

    logging.info(f"Whitelist Set:{wl_set}")
    logging.info(f"Whitelist Set Length: {len(wl_set)}")

    vuln_set = set()

    #
    # If this is NOT a DISTROLESS scan then OpenSCAP findings will be present
    # and should be factored in
    #
    if os.environ.get("DISTROLESS") is None:
        artifacts_path = os.environ["ARTIFACT_STORAGE"]
        oscap = f"{artifacts_path}/scan-results/openscap/report.html"
        oval = f"{artifacts_path}/scan-results/openscap/report-cve.html"

        oscap_cves = get_oscap_fails(oscap)
        oscap_notchecked = get_oscap_notchecked(oscap)
        for oscap in oscap_notchecked:
            oscap_cves.append(oscap)

        for oscap in oscap_cves:
            vuln_set.add(oscap["identifiers"])

        oval_cves = get_oval(oval)
        for oval in oval_cves:
            vuln_set.add(oval)

    tl_cves = get_twistlock_full()
    for tl in tl_cves:
        vuln_set.add(tl["id"])

    anchore_cves = get_anchore_full()
    for anc in anchore_cves:
        vuln_set.add(anc["cve"])

    logging.info(f"Vuln Set: {vuln_set}")
    logging.info(f"Vuln Set Length: {len(vuln_set)}")
    try:
        delta = vuln_set.difference(wl_set)
    except Exception as e:
        logging.exception(
            f"There was an error making the vulnerability delta request {e}"
        )
        return 1

    if len(delta) != 0:
        logging.warning("NON-WHITELISTED VULNERABILITIES FOUND")
        logging.warning(f"Vuln Set Delta: {delta}")
        logging.warning(f"Vuln Set Delta Length: {len(delta)}")
        logging.error(
            f"Scans are not passing 100%. Vuln Set Delta Length: {len(delta)}"
        )
        return 1

    logging.info("ALL VULNERABILITIES WHITELISTED")
    logging.info("Scans are passing 100%")
    return 0


def get_twistlock_full():
    twistlock_file = (
        f"{os.environ['ARTIFACT_STORAGE']}/scan-results/twistlock/twistlock_cve.json"
    )
    with open(twistlock_file, mode="r", encoding="utf-8") as twistlock_json_file:
        json_data = json.load(twistlock_json_file)[0]
        twistlock_data = json_data["vulnerabilities"]
        cves = []
        if twistlock_data is not None:
            for x in twistlock_data:
                cvss = x.get("cvss", "")
                desc = x.get("description", "")
                id = x.get("cve", "")
                link = x.get("link", "")
                packageName = x.get("packageName", "")
                packageVersion = x.get("packageVersion", "")
                severity = x.get("severity", "")
                status = x.get("status", "")
                vecStr = x.get("vecStr", "")
                ret = {
                    "id": id,
                    "cvss": cvss,
                    "desc": desc,
                    "link": link,
                    "packageName": packageName,
                    "packageVersion": packageVersion,
                    "severity": severity,
                    "status": status,
                    "vecStr": vecStr,
                }
                cves.append(ret)
    return cves


def get_anchore_full():
    anchore_file = (
        f"{os.environ['ARTIFACT_STORAGE']}/scan-results/anchore/anchore_security.json"
    )
    with open(anchore_file, "r", encoding="utf-8") as af:
        json_data = json.load(af)
        image_tag = json_data["imageFullTag"]
        anchore_data = json_data["vulnerabilities"]
        cves = []
        for x in anchore_data:
            tag = image_tag
            cve = x["vuln"]
            severity = x["severity"]
            package = x["package"]
            package_path = x["package_path"]
            fix = x["fix"]
            url = x["url"]

            ret = {
                "tag": tag,
                "cve": cve,
                "severity": severity,
                "package": package,
                "package_path": package_path,
                "fix": fix,
                "url": url,
            }

            cves.append(ret)
        return cves


def get_oval(oval_file):
    oscap = open(oval_file, "r", encoding="utf-8")
    soup = BeautifulSoup(oscap, "html.parser")
    results_bad = soup.find_all("tr", class_=["resultbadA", "resultbadB"])

    cves = []
    for x in results_bad:
        y = x.find_all(target="_blank")
        references = set()
        for t in y:
            references.add(t.text)

        for ref in references:
            cves.append(ref)
    return cves


def get_oscap_fails(oscap_file):
    with open(oscap_file, "r", encoding="utf-8") as of:
        soup = BeautifulSoup(of, "html.parser")
        divs = soup.find("div", id="result-details")

        scan_date = soup.find("th", text="Finished at")
        finished_at = scan_date.find_next_sibling("td").text

        regex = re.compile(".*rule-detail-fail.*")

        fails = divs.find_all("div", {"class": regex})

        cces = []
        for x in fails:
            title = x.find("h3", {"class": "panel-title"}).text
            table = x.find("table", {"class": "table table-striped table-bordered"})

            ruleid = table.find("td", text="Rule ID").find_next_sibling("td").text
            result = table.find("td", text="Result").find_next_sibling("td").text
            severity = table.find("td", text="Severity").find_next_sibling("td").text
            ident = table.find(
                "td", text="Identifiers and References"
            ).find_next_sibling("td")
            if ident.find("abbr"):
                identifiers = ident.find("abbr").text

            references = ident.find_all("a", href=True)
            refs = []
            for j in references:
                refs.append(j.text)

            desc = table.find("td", text="Description").find_next_sibling("td").text
            rationale = table.find("td", text="Rationale").find_next_sibling("td").text

            ret = {
                "title": title,
                "ruleid": ruleid,
                "result": result,
                "severity": severity,
                "identifiers": identifiers,
                "refs": refs,
                "desc": desc,
                "rationale": rationale,
                "scanned_date": finished_at,
            }
            cces.append(ret)
        return cces


def get_oscap_notchecked(oscap_file):
    with open(oscap_file, "r", encoding="utf-8") as of:
        soup = BeautifulSoup(of, "html.parser")
        divs = soup.find("div", id="result-details")

        scan_date = soup.find("th", text="Finished at")
        finished_at = scan_date.find_next_sibling("td").text

        regex = re.compile(".*rule-detail-notchecked.*")

        notchecked = divs.find_all("div", {"class": regex})

        cces_notchecked = []
        for x in notchecked:
            title = x.find("h3", {"class": "panel-title"}).text
            table = x.find("table", {"class": "table table-striped table-bordered"})

            ruleid = table.find("td", text="Rule ID").find_next_sibling("td").text
            result = table.find("td", text="Result").find_next_sibling("td").text
            severity = table.find("td", text="Severity").find_next_sibling("td").text
            ident = table.find(
                "td", text="Identifiers and References"
            ).find_next_sibling("td")
            if ident.find("abbr"):
                identifiers = ident.find("abbr").text

            references = ident.find_all("a", href=True)
            refs = []
            for j in references:
                refs.append(j.text)

            desc = table.find("td", text="Description").find_next_sibling("td").text
            rationale = table.find("td", text="Rationale").find_next_sibling("td").text

            ret = {
                "title": title,
                "ruleid": ruleid,
                "result": result,
                "severity": severity,
                "identifiers": identifiers,
                "refs": refs,
                "desc": desc,
                "rationale": rationale,
                "scanned_date": finished_at,
            }
            cces_notchecked.append(ret)
        return cces_notchecked


def get_greylist_file_contents(image_path, branch):
    greylist_file_path = f"{image_path}/{image_path.split('/')[-1]}.greylist"
    try:
        gl = init(dccscr_project_id)
        f = gl.files.get(file_path=greylist_file_path, ref=branch)
    except gitlab.exceptions.GitlabError:
        logging.error(f"Whitelist retrieval attempted: {greylist_file_path}")
        logging.error(f"Error retrieving whitelist file: {sys.exc_info()[1]}")
        sys.exit(1)

    try:
        contents = json.loads(f.decode())
    except ValueError as e:
        logging.error("JSON object issue: {e}")
        sys.exit(1)

    return contents


# TODO: Need to update this to use hardening_manifest.yaml
def get_complete_whitelist_for_image(image_name, whitelist_branch, hardening_manifest=None, total_whitelist=list()):
    greylist = get_greylist_file_contents(image_path=image_name, branch=whitelist_branch)
    logging.info(f"Grabbing CVEs for: {image_name}")

    for vuln in whitelisted_vulns(im_name=image_name, contents=greylist):
        total_whitelist.append(vuln)

    while True:
        parent_image = greylist["image_parent_name"]
        if parent_image == "":
            break

        logging.info(f"Grabbing CVEs for: {parent_image}")
        greylist = get_greylist_file_contents(image_path=parent_image, branch=whitelist_branch)

        for vuln in whitelisted_vulns(im_name=parent_image, contents=greylist):
            total_whitelist.append(vuln)

    logging.info(f"Found {len(total_whitelist)} total whitelisted CVEs")

    return total_whitelist


def whitelisted_vulns(im_name, contents):
    wl = []
    for v in contents["whitelisted_vulnerabilities"]:
        tar = Vuln(v, im_name)
        wl.append(tar)
    return wl


def init(pid):
    gl = gitlab.Gitlab(gitlab_url)
    return gl.projects.get(pid)


class Vuln:
    vuln_id = ""
    vuln_desc = ""
    vuln_source = ""
    whitelist_source = ""
    status = ""
    approved_date = ""
    approved_by = ""
    justification = ""

    def __repr__(self):
        return f"Vuln: {self.vulnerability} - {self.vuln_source} - {self.whitelist_source} - {self.status} - {self.approved_by}"

    def __str__(self):
        return f"Vuln: {self.vulnerability} - {self.vuln_source} - {self.whitelist_source} - {self.status} - {self.approved_by}"

    def __init__(self, v, im_name):
        self.vulnerability = v["vulnerability"]
        self.vuln_description = v["vuln_description"]
        self.vuln_source = v["vuln_source"]
        self.status = v["status"]
        self.approved_date = v["approved_date"]
        self.approved_by = v["approved_by"]
        self.justification = v["justification"]
        self.whitelist_source = im_name


if __name__ == "__main__":
    main()  # with if
