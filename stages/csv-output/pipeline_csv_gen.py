#!/usr/bin/env python3

import csv
import yaml
import gitlab
import sys
import re
import json
import os
import argparse
import pathlib
import logging
import mysql.connector
from mysql.connector import Error
from bs4 import BeautifulSoup


# The InheritableTriggerIds variable contains a list of Anchore compliance trigger_ids
# that are inheritable by child images.
inheritableTriggerIds = [
    "639f6f1177735759703e928c14714a59",
    "c2e44319ae5b3b040044d8ae116d1c2f",
    "698044205a9c4a6d48b7937e66a6bf4f",
    "463a9a24225c26f7a5bf3f38908e5cb3",
    "bcd159901fe47efddae5c095b4b0d7fd",
    "320a97c6816565eedf3545833df99dd0",
    "953dfbea1b1e9d5829fbed2e390bd3af",
    "e7573262736ef52353cde3bae2617782",
    "addbb93c22e9b0988b8b40392a4538cb",
    "3456a263793066e9b5063ada6e47917d",
    "3e5fad1c039f3ecfd1dcdc94d2f1f9a0",
    "abb121e9621abdd452f65844954cf1c1",
    "34de21e516c0ca50a96e5386f163f8bf",
    "c4ad80832b361f81df2a31e5b6b09864",
]


def main():
    global csv_dir

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

    parser = argparse.ArgumentParser(
        description="DCCSCR processing of CVE reports from various sources"
    )
    parser.add_argument("--twistlock", help="location of the twistlock JSON scan file")
    parser.add_argument("--oscap", help="location of the oscap scan HTML file")
    parser.add_argument("--oval", help="location of the oval scan HTML file")
    parser.add_argument(
        "--anchore-sec", help="location of the anchore_security.json scan file"
    )
    parser.add_argument(
        "--anchore-gates", help="location of the anchore_gates.json scan file"
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        dest="output_dir",
        help="directory in which to write CSV output",
        default="./",
    )
    args = parser.parse_args()

    csv_dir = args.output_dir
    if not os.path.exists(csv_dir):
        os.mkdir(csv_dir)

    # Get the hardening manifest and additional parameters for _get_complete_whitelist_for_image
    hardening_manifest = _load_local_hardening_manifest()
    if hardening_manifest is None:
        logging.error("Please update your project to contain a hardening_manifest.yaml")
    image_name = hardening_manifest["name"]
    wl_branch = os.getenv("WL_TARGET_BRANCH", default="master")

    # get cves and justifications from VAT
    total_whitelist = _get_complete_whitelist_for_image(
        image_name, wl_branch, hardening_manifest
    )

    # Get all justifications

    print("Gathering list of all justifications...", end="", flush=True)

    jOpenscap, jTwistlock, jAnchore = _get_justifications(total_whitelist, image_name)
    oscap_fail_count = 0
    oval_fail_count = 0
    twist_fail_count = 0
    anc_sec_count = 0
    anc_gate_count = 0
    if args.oscap:
        oscap_fail_count = generate_oscap_report(args.oscap, jOpenscap)
    else:
        generate_blank_oscap_report()
    if args.oval:
        oval_fail_count = generate_oval_report(args.oval)
    else:
        generate_blank_oval_report()
    if args.twistlock:
        twist_fail_count = generate_twistlock_report(args.twistlock, jTwistlock)
    if args.anchore_sec:
        anc_sec_count = generate_anchore_sec_report(args.anchore_sec, jAnchore)
    if args.anchore_gates:
        anc_gate_count = generate_anchore_gates_report(args.anchore_gates, jAnchore)

    generate_summary_report(
        oscap_fail_count,
        oval_fail_count,
        twist_fail_count,
        anc_sec_count,
        anc_gate_count,
    )
    # csv_dir = sys.argv[6]
    # if not os.path.exists(csv_dir):
    #     os.mkdir(csv_dir)
    # generate_all_reports(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])


# NOT USED IN PIPELINE: GENERATES ALL OF THE REPORTS FOR ALL OF THE THINGS INCLUDING A SUMMARY INTO /tmp/csvs/
def generate_all_reports(oscap, oval, twistlock, anchore_sec, anchore_gates):
    oscap_fail_count = generate_oscap_report(oscap)
    oval_fail_count = generate_oval_report(oval)
    twist_fail_count = generate_twistlock_report(twistlock)
    anc_sec_count = generate_anchore_sec_report(anchore_sec)
    anc_gate_count = generate_anchore_gates_report(anchore_gates)

    generate_summary_report(
        oscap_fail_count,
        oval_fail_count,
        twist_fail_count,
        anc_sec_count,
        anc_gate_count,
    )


def _load_local_hardening_manifest():
    """
    Load up the hardening_manifest.yaml file as a dictionary. Search for the file in
    the immediate repo first, if that is not found then search for the generated file.

    If neither are found then return None and let the calling function handle the error.

    """
    artifacts_path = os.environ["ARTIFACT_STORAGE"]
    paths = [
        pathlib.Path("hardening_manifest.yaml"),
        # Check for the generated hardening manifest. This method will be deprecated.
        pathlib.Path(artifacts_path, "preflight", "hardening_manifest.yaml"),
    ]

    for path in paths:
        logging.debug(f"Looking for {path}")
        if path.is_file():
            logging.debug(f"Using {path}")
            with path.open("r") as f:
                return yaml.safe_load(f)
        else:
            logging.debug(f"Couldn't find {path}")
    return None


def _load_remote_hardening_manifest(project, branch="master"):
    """
    Load up a hardening_manifest.yaml from a remote repository.

    If the manifest file is not found then None is returned. A warning will print
    to console to communicate which repository does not have a hardening manifest.

    """
    if project == "":
        return None

    logging.debug(f"Attempting to load hardening_manifest from {project}")

    try:
        gl = gitlab.Gitlab(os.environ["REPO1_URL"])
        proj = gl.projects.get(f"dsop/{project}", lazy=True)
        logging.debug(f"Connecting to dsop/{project}")

        hardening_manifest = proj.files.get(
            file_path="hardening_manifest.yaml", ref=branch
        )
        return yaml.safe_load(hardening_manifest.decode())

    except gitlab.exceptions.GitlabError:
        logging.info(
            "Could not load hardening_manifest. Defaulting backwards compatibility."
        )
        logging.warning(
            f"This method will be deprecated soon, please switch {project} to hardening_manifest.yaml"
        )

    except yaml.YAMLError as e:
        logging.error("Could not load the hardening_manifest.yaml")
        logging.error(e)
        sys.exit(1)

    return None


def _next_ancestor(image_path, whitelist_branch, hardening_manifest=None):
    """
    Grabs the parent image path from the current context. Will initially attempt to load
    a new hardening manifest and then pull the parent image from there. Otherwise it will
    default to the old method of using the greylist.

    If neither the hardening_manifest.yaml or the greylist field can be found then there
    is a weird mismatch during migration that needs further inspection.

    """

    # Try to get the parent image out of the local hardening_manifest.
    if hardening_manifest:
        return (
            hardening_manifest["args"]["BASE_IMAGE"],
            hardening_manifest["args"]["BASE_TAG"],
        )

    # Try to load the hardening manifest from a remote repo.
    hm = _load_remote_hardening_manifest(project=image_path)
    if hm is not None:
        return (hm["args"]["BASE_IMAGE"], hm["args"]["BASE_TAG"])

    try:
        greylist = _get_greylist_file_contents(
            image_path=image_path, branch=whitelist_branch
        )
        return (greylist["image_parent_name"], greylist["image_parent_tag"])
    except KeyError as e:
        logging.error("Looks like a hardening_manifest.yaml cannot be found")
        logging.error(
            "Looks like the greylist has been updated to remove fields that should be present in hardening_manifest.yaml"
        )
        logging.error(e)
        sys.exit(1)


def _get_greylist_file_contents(image_path, branch):
    """
    Grab the contents of a greylist file. Takes in the path to the image and
    determines the appropriate greylist.

    """
    greylist_file_path = f"{image_path}/{image_path.split('/')[-1]}.greylist"
    try:
        gl = gitlab.Gitlab(os.environ["REPO1_URL"])
        proj = gl.projects.get("dsop/dccscr-whitelists", lazy=True)
        f = proj.files.get(file_path=greylist_file_path, ref=branch)

    except gitlab.exceptions.GitlabError:
        logging.error(
            f"Whitelist retrieval attempted: {greylist_file_path} on {branch}"
        )
        logging.error(f"Error retrieving whitelist file: {sys.exc_info()[1]}")
        sys.exit(1)

    try:
        contents = json.loads(f.decode())
    except ValueError as e:
        logging.error("Could not load greylist as json")
        logging.error(e)
        sys.exit(1)

    return contents


def _connect_to_db():
    """
    @return mariadb connection for the VAT
    """
    conn = None
    try:
        conn = mysql.connector.connect(
            host=os.environ["vat_db_host"],
            database=os.environ["vat_db_database_name"],
            user=os.environ["vat_db_connection_user"],
            passwd=os.environ["vat_db_connection_pass"],
        )
        if conn.is_connected():
            # there are many connections to db so this should be uncommented
            # for troubleshooting
            logging.debug(
                "Connected to the host %s with user %s",
                os.environ["vat_db_host"],
                os.environ["vat_db_connection_user"],
            )
        else:
            logging.critical("Failed to connect to DB")
            sys.exit(1)
    except Error as err:
        logging.critical(err)
        if conn is not None and conn.is_connected():
            conn.close()
        sys.exit(1)

    return conn


def _vat_vuln_query(im_name, im_version):
    """
    Gather the vulns for an image as a list of tuples to add to the total_whitelist.
    Collects all findings for the source image layer in VAT

    """
    conn = None
    result = None
    try:
        conn = _connect_to_db()
        cursor = conn.cursor(buffered=True)
        # TODO: add new scan logic
        query = """SELECT c.name as container
                , c.version
                , CASE WHEN cl.type is NULL THEN "Pending" ELSE cl.type END as container_approval_status
                , f.finding
                , f.scan_source
                , f.in_current_scan
                , CASE
                WHEN fl.type is NULL THEN "Pending"
                WHEN cl.date_time is NULL and fl.type = "Approve" THEN "Reviewed"
                WHEN fl.date_time > cl.date_time and fl.type = "Approve" THEN "Reviewed"
                ELSE fl.type END as finding_status
                ,fl.text as approval_comments
                , fl2.text as justification
                , sr.description
                , f.package
                , f.package_path
                FROM findings_approvals f
                INNER JOIN containers c on f.imageid = c.id
                LEFT JOIN findings_log fl on f.id = fl.approval_id
                AND fl.id in (SELECT max(id) from findings_log WHERE type != "Justification" group by approval_id)
                LEFT JOIN findings_log fl2 on f.id = fl2.approval_id
                AND fl2.id in (SELECT max(id) from findings_log WHERE type = "Justification" group by approval_id)
                LEFT JOIN container_log cl on c.id = cl.imageid
                AND cl.id in (SELECT max(id) from container_log group by imageid)
                LEFT JOIN scan_results sr on c.id = sr.imageid AND f.finding = sr.finding AND f.package = sr.package AND f.package_path = sr.package_path
                AND jenkins_run in (SELECT max(jenkins_run) from scan_results WHERE imageid = c.id AND finding = f.finding AND package = f.package)
                WHERE f.inherited_id is NULL
                AND c.name=%s and c.version=%s
                AND f.in_current_scan = 1;"""
        cursor.execute(query, (im_name, im_version))
        result = cursor.fetchall()
    except Error as error:
        logging.info(error)
    finally:
        if conn is not None and conn.is_connected():
            conn.close()
    return result


def _get_vulns_from_query(row):
    """
    For each row in result (returned from VAT db query), create a dictionary gathering
    the necessary items to be compared for each entry in the twistlock, anchore and openscap scans.

    Each row should have 12 items in the form:
    (image_name, image_version, container_status, vuln, source (e.g. anchore_cve), in_current_scan (bool)
    vuln_status (e.g. Approve), approval_comments, justification, description, package, package_path)

    For anchore_comp and anchore_cve, the vuln_description is the package instead of the description.

    example: ('redhat/ubi/ubi8', '8.3', 'Approve', 'CCE-82360-9', 'oscap_comp', 1, 'Approve', 'Approved, imported from spreadsheet.',
    'Not applicable. This performs automatic updates to installed packages which does not apply to immutable containers.',
    'Enable dnf-automatic Timer', 'N/A', 'N/A')

    """
    vuln_dict = {}
    vuln_dict["whitelist_source"] = row[0]
    vuln_dict["version"] = row[1]
    vuln_dict["vulnerability"] = row[3]
    vuln_dict["vuln_source"] = row[4]
    vuln_dict["status"] = row[6]
    vuln_dict["justification"] = row[8]
    if row[4] and row[4] == "anchore_cve":
        vuln_dict["vuln_description"] = row[10]
    elif row[4] and row[4] == "anchore_comp":
        vuln_dict["vuln_description"] = row[9].split("\n")[0]
    else:
        vuln_dict["vuln_description"] = row[9]
    return vuln_dict


def _get_complete_whitelist_for_image(image_name, whitelist_branch, hardening_manifest):
    """
    Pull all whitelisted CVEs for an image. Walk through the ancestry of a given
    image and grab all of the approved vulnerabilities in VAT associated with w layer.

    """
    total_whitelist = []

    logging.info(f"Grabbing CVEs for: {image_name}")
    # get cves from vat
    result = _vat_vuln_query(os.environ["IMAGE_NAME"], os.environ["IMAGE_VERSION"])
    # parse CVEs from VAT query
    # empty list is returned if no entry or no cves. NoneType only returned if error.
    # logging.info(result[0])
    if result is None:
        logging.error("No results from vat. Fatal error.")
        sys.exit(1)
    else:
        for row in result:
            logging.debug(row)
            vuln_dict = _get_vulns_from_query(row)
            if vuln_dict["status"] and vuln_dict["status"].lower() == "approve":
                total_whitelist.append(vuln_dict)
                logging.debug(vuln_dict)
            else:
                logging.debug(
                    "There is no approval status present in result or cve not approved"
                )

    logging.debug(
        "Length of total whitelist for source image: " + str(len(total_whitelist))
    )

    #
    # Use the local hardening manifest to get the first parent. From here *only* the
    # the master branch should be used for the ancestry.
    #
    parent_image_name, parent_image_version = _next_ancestor(
        image_path=image_name,
        whitelist_branch=whitelist_branch,
        hardening_manifest=hardening_manifest,
    )

    # get parent cves from VAT
    while parent_image_name:
        logging.info(f"Grabbing CVEs for: {parent_image_name}")

        result = _vat_vuln_query(parent_image_name, parent_image_version)

        for row in result:
            vuln_dict = _get_vulns_from_query(row)
            if vuln_dict["status"] and vuln_dict["status"].lower() == "approve":
                total_whitelist.append(vuln_dict)

        parent_image_name, parent_image_version = _next_ancestor(
            image_path=parent_image_name,
            whitelist_branch=whitelist_branch,
        )

    logging.info(f"Found {len(total_whitelist)} total whitelisted CVEs")
    return total_whitelist


def _get_justifications(total_whitelist, sourceImageName):
    """
    Gather all justifications for any approved CVE for anchore, twistlock and openscap.
    Keys are in the form vuln-packagename (anchore_cve), vuln-description (twistlock), or vuln (anchore_comp, openscap).

    Examples:
        CVE-2020-13434-sqlite-libs-3.26.0-11.el8 (anchore key)
        CVE-2020-8285-A malicious server can use... (twistlock key, truncated)
        CCE-82315-3 (openscap key)

    """
    cveOpenscap = {}
    cveTwistlock = {}
    cveAnchore = {}

    # Loop through all the greylist files
    # Getting results from VAT, just loop all findings, check if finding is related to base_images or source image
    # Loop through the findings and create the corresponding dict object based on the vuln_source
    for finding in total_whitelist:
        if "vulnerability" in finding.keys():
            cveID = finding["vulnerability"] + "-" + finding["vuln_description"]
            openscapID = finding["vulnerability"]
            trigger_id = finding["vulnerability"]
            logging.debug(cveID)
            # Twistlock finding
            if finding["vuln_source"] == "twistlock_cve":
                if finding["whitelist_source"] == sourceImageName:
                    cveTwistlock[cveID] = finding["justification"]
                else:
                    cveTwistlock[cveID] = "Inherited from base image."
                    logging.debug("Twistlock inherited cve")

            # Anchore finding
            elif (
                finding["vuln_source"] == "anchore_cve"
                or finding["vuln_source"] == "anchore_comp"
            ):
                if finding["whitelist_source"] == sourceImageName:
                    cveAnchore[cveID] = finding["justification"]
                    cveAnchore[trigger_id] = finding["justification"]
                else:
                    logging.debug("Anchore inherited cve")
                    cveAnchore[cveID] = "Inherited from base image."
                    if trigger_id in inheritableTriggerIds:
                        cveAnchore[trigger_id] = "Inherited from base image."

            # OpenSCAP finding
            elif finding["vuln_source"] == "oscap_comp":
                if finding["whitelist_source"] == sourceImageName:
                    cveOpenscap[openscapID] = finding["justification"]
                else:
                    cveOpenscap[openscapID] = "Inherited from base image."
                    logging.debug("Oscap inherited cve")
        # print(cveAnchore)
    return cveOpenscap, cveTwistlock, cveAnchore


# Blank OSCAP Report
def generate_blank_oscap_report():
    oscap_report = open(csv_dir + "oscap.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(oscap_report)
    csv_writer.writerow(
        ["OpenSCAP Scan Skipped Due to Base Image Used", "", "", "", "", "", "", "", ""]
    )
    oscap_report.close()


# Blank oval Report
def generate_blank_oval_report():
    oval_report = open(csv_dir + "oval.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(oval_report)
    csv_writer.writerow(
        ["OpenSCAP Scan Skipped Due to Base Image Used", "", "", "", ""]
    )
    oval_report.close()


# SUMMARY REPORT
def generate_summary_report(osc, ovf, tlf, asf, agf):
    sum_data = open(csv_dir + "summary.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(sum_data)

    header = ["Scan", "Automated Findings", "Manual Checks", "Total"]
    # if the osc arg type is an int, the scan was skipped so output zero values
    if type(osc) == int:
        osl = ["OpenSCAP - DISA Compliance", 0, 0, 0]
    # osc arg is a tuple, meaning the generate_oscap_report and generate_oval_report functions were run
    else:
        osl = ["OpenSCAP - DISA Compliance", osc[0], osc[1], osc[0] + osc[1]]
    ovf = ["OpenSCAP - OVAL Results", int(ovf or 0), 0, int(ovf or 0)]
    ancl = ["Anchore CVE Results", int(asf or 0), 0, int(asf or 0)]
    ancc = ["Anchore Compliance Results", int(agf[0] or 0), 0, int(agf[0] or 0)]
    twl = ["Twistlock Vulnerability Results", int(tlf or 0), 0, int(tlf or 0)]

    csv_writer.writerow(header)
    csv_writer.writerow(osl)
    csv_writer.writerow(ovf)
    csv_writer.writerow(twl)
    csv_writer.writerow(ancl)
    csv_writer.writerow(ancc)
    csv_writer.writerow(
        [
            "Totals",
            osl[1] + ovf[1] + ancl[1] + ancc[1] + twl[1],
            osl[2] + ovf[2] + ancl[2] + ancc[2] + twl[2],
            osl[3] + ovf[3] + ancl[3] + ancc[3] + twl[3],
        ]
    )

    csv_writer.writerow("")
    # date_str = 'Scans performed on: ' + str(osc[2])
    # csv_writer.writerow(['Scans performed on:', ]) # need date scanned
    sha_str = "Scans performed on container layer sha256:" + agf[1] + ",,,"
    csv_writer.writerow([sha_str])
    sum_data.close()


# Generate csv for OSCAP findings with justifications
def generate_oscap_report(oscap, justifications):
    oscap_cves = get_oscap_full(oscap, justifications)
    oscap_data = open(csv_dir + "oscap.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(oscap_data)
    count = 0
    fail_count = 0
    nc_count = 0
    scanned = ""
    for line in oscap_cves:
        if count == 0:
            header = line.keys()
            csv_writer.writerow(header)
            count += 1
        if line["result"] == "fail":
            fail_count += 1
        elif line["result"] == "notchecked":
            nc_count += 1
        scanned = line["scanned_date"]
        try:
            csv_writer.writerow(line.values())
        except Exception as e:
            print("problem writing line:", line.values())
            raise e
    oscap_data.close()
    return fail_count, nc_count, scanned


# Get full OSCAP report with justifications for csv export
def get_oscap_full(oscap_file, justifications):
    with open(oscap_file, mode="r", encoding="utf-8") as of:
        soup = BeautifulSoup(of, "html.parser")
        divs = soup.find("div", id="result-details")

        scan_date = soup.find("th", text="Finished at")
        finished_at = scan_date.find_next_sibling("td").text
        id_regex = re.compile(".*rule-detail-.*")
        all = divs.find_all("div", {"class": id_regex})

        cces = []
        for x in all:
            # Assign identifiers to null value otherwise it fails when parsing non-RHEL scan results
            identifiers = None

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

            cve_justification = ""
            id = identifiers
            if id in justifications.keys():
                cve_justification = justifications[id]

            ret = {
                "title": title,
                # 'table': table,
                "ruleid": ruleid,
                "result": result,
                "severity": severity,
                "identifiers": identifiers,
                "refs": refs,
                "desc": desc,
                "rationale": rationale,
                "scanned_date": finished_at,
                "Justification": cve_justification,
            }
            cces.append(ret)
        return cces


# Generate oval csv
def generate_oval_report(oval):
    oval_cves = get_oval_full(oval)
    oval_data = open(csv_dir + "oval.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(oval_data)
    count = 0
    fail_count = 0
    for line in oval_cves:
        if count == 0:
            header = line.keys()
            csv_writer.writerow(header)
            count += 1
        if line["result"] == "true":
            fail_count += 1
        csv_writer.writerow(line.values())
    oval_data.close()
    return fail_count


# Get OVAL report for csv export
def get_oval_full(oval_file):
    oscap = open(oval_file, "r", encoding="utf-8")
    soup = BeautifulSoup(oscap, "html.parser")
    results_bad = soup.find_all("tr", class_=["resultbadA", "resultbadB"])
    results_good = soup.find_all("tr", class_=["resultgoodA", "resultgoodB"])

    cves = []
    for x in results_bad + results_good:
        id = x.find("td")
        result = id.find_next_sibling("td")
        cls = result.find_next_sibling("td")
        y = x.find_all(target="_blank")
        references = set()
        for t in y:
            references.add(t.text)
        title = cls.find_next_sibling("td").find_next_sibling("td")

        for ref in references:
            ret = {
                "id": id.text,
                "result": result.text,
                "cls": cls.text,
                "ref": ref,
                "title": title.text,
            }
            cves.append(ret)
    return cves


# Get results from Twistlock report for csv export
def generate_twistlock_report(twistlock_cve_json, justifications):
    with open(twistlock_cve_json, mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
        cves = []
        if json_data[0]["vulnerabilities"]:
            for d in json_data[0]["vulnerabilities"]:
                # get associated justification if one exists
                id = ""
                cve_justification = ""
                if d["description"]:
                    id = d["cve"] + "-" + d["description"]
                else:
                    id = d["cve"]
                if id in justifications.keys():
                    cve_justification = justifications[id]
                # else cve_justification is ""
                cves.append(
                    {
                        "id": d["cve"],
                        "cvss": d["cvss"],
                        "desc": d["description"],
                        "link": d["link"],
                        "packageName": d["packageName"],
                        "packageVersion": d["packageVersion"],
                        "severity": d["severity"],
                        "status": d["status"],
                        "vecStr": d["vecStr"],
                        "Justification": cve_justification,
                    }
                )
        else:
            cves = []

    fieldnames = [
        "id",
        "cvss",
        "desc",
        "link",
        "packageName",
        "packageVersion",
        "severity",
        "status",
        "vecStr",
        "Justification",
    ]

    _write_csv_from_dict_list(dict_list=cves, fieldnames=fieldnames, filename="tl.csv")

    return len(cves)


def _write_csv_from_dict_list(dict_list, fieldnames, filename):
    """
    Create csv file based off prepared data. The data must be provided as a list
    of dictionaries and the rest will be taken care of.

    """
    filepath = pathlib.Path(csv_dir, filename)

    with filepath.open(mode="w", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        if dict_list:
            writer.writerows(dict_list)


# Get results from Anchore security for csv export, becomes anchore cve spreadsheet
def generate_anchore_sec_report(anchore_security_json, justifications):
    with open(anchore_security_json, mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
        cves = []
        for d in json_data["vulnerabilities"]:
            cve_justification = ""
            id = d["vuln"] + "-" + d["package"]
            if id in justifications.keys():
                cve_justification = justifications[id]
            cves.append(
                {
                    "tag": json_data["imageFullTag"],
                    "cve": d["vuln"],
                    "severity": d["severity"],
                    "package": d["package"],
                    "package_path": d["package_path"],
                    "fix": d["fix"],
                    "url": d["url"],
                    "inherited": d.get("inherited_from_base") or "no_data",
                    "Justification": cve_justification,
                }
            )

    fieldnames = [
        "tag",
        "cve",
        "severity",
        "package",
        "package_path",
        "fix",
        "url",
        "inherited",
        "Justification",
    ]

    _write_csv_from_dict_list(
        dict_list=cves, fieldnames=fieldnames, filename="anchore_security.csv"
    )

    return len(cves)


# Get results of Anchore gates for csv export, becomes anchore compliance spreadsheet
def generate_anchore_gates_report(anchore_gates_json, justifications):
    with open(anchore_gates_json, encoding="utf-8") as f:
        json_data = json.load(f)
        sha = list(json_data.keys())[0]
        anchore_data = json_data[sha]["result"]["rows"]

    gates = []
    stop_count = 0
    image_id = "unable_to_determine"
    for ad in anchore_data:
        gate = {
            "image_id": ad[0],
            "repo_tag": ad[1],
            "trigger_id": ad[2],
            "gate": ad[3],
            "trigger": ad[4],
            "check_output": ad[5],
            "gate_action": ad[6],
            "policy_id": ad[8],
        }

        if ad[7]:
            gate["matched_rule_id"] = ad[7]["matched_rule_id"]
            gate["whitelist_id"] = ad[7]["whitelist_id"]
            gate["whitelist_name"] = ad[7]["whitelist_name"]
        else:
            gate["matched_rule_id"] = ""
            gate["whitelist_id"] = ""
            gate["whitelist_name"] = ""

        try:
            gate["inherited"] = ad[9]
            if gate["gate"] == "dockerfile":
                gate["inherited"] = False
        except IndexError:
            gate["inherited"] = "no_data"

        cve_justification = ""
        # ad[2] is trigger_id -- e.g. CVE-2020-####
        id = ad[2]
        if ad[4] == "package":
            cve_justification = "See Anchore CVE Results sheet"

        if id in justifications.keys():
            cve_justification = justifications[id]
        gate["Justification"] = cve_justification

        gates.append(gate)

        if gate["gate_action"] == "stop":
            stop_count += 1

        image_id = gate["image_id"]

    fieldnames = [
        "image_id",
        "repo_tag",
        "trigger_id",
        "gate",
        "trigger",
        "check_output",
        "gate_action",
        "policy_id",
        "matched_rule_id",
        "whitelist_id",
        "whitelist_name",
        "inherited",
        "Justification",
    ]

    _write_csv_from_dict_list(
        dict_list=gates, fieldnames=fieldnames, filename="anchore_gates.csv"
    )
    return stop_count, image_id


if __name__ == "__main__":
    main()  # with if

