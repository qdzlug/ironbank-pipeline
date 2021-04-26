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
import xml.etree.ElementTree as etree

from scanners import anchore
from scanners.helper import write_csv_from_dict_list

# The InheritableTriggerIds variable contains a list of Anchore compliance trigger_ids
# that are inheritable by child images.
_inheritable_trigger_ids = [
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
    parser.add_argument("--sbom-dir", help="location of the anchore content directory")
    args = parser.parse_args()

    # Create the csv directory if not present
    pathlib.Path(args.output_dir).mkdir(parents=True, exist_ok=True)

    # Get the hardening manifest and additional parameters for _get_complete_whitelist_for_image
    hardening_manifest = _load_local_hardening_manifest()
    if hardening_manifest is None:
        logging.error("Please update your project to contain a hardening_manifest.yaml")
        sys.exit(1)

    image_name = hardening_manifest["name"]
    wl_branch = os.environ.get("WL_TARGET_BRANCH", default="master")

    # get cves and justifications from VAT
    total_whitelist = _get_complete_whitelist_for_image(
        image_name, wl_branch, hardening_manifest
    )

    # Get all justifications
    logging.info("Gathering list of all justifications...")

    j_openscap, j_twistlock, j_anchore_cve, j_anchore_comp = _get_justifications(
        total_whitelist, image_name
    )
    oscap_fail_count = 0
    oval_fail_count = 0
    twist_fail_count = 0
    anchore_num_cves = 0
    anchore_compliance = 0
    if args.oscap:
        oscap_fail_count = generate_oscap_report(
            args.oscap, j_openscap, csv_dir=args.output_dir
        )
    else:
        generate_blank_oscap_report(csv_dir=args.output_dir)
    if args.oval:
        oval_fail_count = generate_oval_report(args.oval, csv_dir=args.output_dir)
    else:
        generate_blank_oval_report(csv_dir=args.output_dir)
    if args.twistlock:
        twist_fail_count = generate_twistlock_report(
            args.twistlock, j_twistlock, csv_dir=args.output_dir
        )
    if args.anchore_sec:
        anchore_num_cves = anchore.vulnerability_report(
            csv_dir=args.output_dir,
            anchore_security_json=args.anchore_sec,
            justifications=j_anchore_cve,
        )
    if args.anchore_gates:
        anchore_compliance = anchore.compliance_report(
            csv_dir=args.output_dir,
            anchore_gates_json=args.anchore_gates,
            justifications=j_anchore_comp,
        )
    if args.sbom_dir:
        anchore.sbom_report(csv_dir=args.output_dir, sbom_dir=args.sbom_dir)

    generate_summary_report(
        csv_dir=args.output_dir,
        osc=oscap_fail_count,
        ovf=oval_fail_count,
        tlf=twist_fail_count,
        anchore_num_cves=anchore_num_cves,
        anchore_compliance=anchore_compliance,
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
        logging.error("Could not load hardening_manifest.")
        sys.exit(1)

    except yaml.YAMLError as e:
        logging.error("Could not load the hardening_manifest.yaml")
        logging.error(e)
        sys.exit(1)

    return None


def _next_ancestor(image_path, whitelist_branch, hardening_manifest=None):
    """
    Grabs the parent image path from the current context. Will initially attempt to load
    a new hardening manifest and then pull the parent image from there.

    If the hardening_manifest.yaml can't be found then there
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
    else:
        logging.error(
            "hardening_manifest.yaml does not exist for "
            + image_path
            + ". Please add a hardening_manifest.yaml file to this project"
        )
        logging.error("Exiting.")
        sys.exit(1)


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
    Returns non inherited vulnerabilities for a specific container
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
                , fl1.in_current_scan
                , fl1.state as finding_status
                , fl1.record_text as approval_comments
                , fl2.record_text as justification
                , sr.description
                , f.package
                , f.package_path
                FROM findings f
                INNER JOIN containers c on f.container_id = c.id
                INNER JOIN finding_logs fl on active = 1 and in_current_scan = 1 and inherited = 0 and f.id = fl.finding_id
                LEFT JOIN container_log cl on c.id = cl.imageid AND cl.id in (SELECT max(id) from container_log group by imageid)
                LEFT JOIN finding_logs fl1 ON fl1.record_type_active = 1 and fl1.record_type = 'state_change' and f.id = fl1.finding_id
                LEFT JOIN finding_logs fl2 ON fl2.record_type_active = 1 and fl2.record_type = 'justification' and f.id = fl2.finding_id
                LEFT JOIN finding_scan_results sr on f.id = sr.finding_id and sr.active = 1
                WHERE c.name = %s and c.version = %s;"""
        cursor.execute(query, (im_name, im_version))
        result = cursor.fetchall()
    except Error as error:
        logging.info(error)
        sys.exit(1)
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
    vuln_status (e.g. Approved), approval_comments, justification, description, package, package_path)

    For anchore_comp and anchore_cve, the vuln_description is the package instead of the description.

    example: ('redhat/ubi/ubi8', '8.3', 'Approved', 'CCE-82360-9', 'oscap_comp', 1, 'approved', 'Approved, imported from spreadsheet.',
    'Not applicable. This performs automatic updates to installed packages which does not apply to immutable containers.',
    'Enable dnf-automatic Timer', 'N/A', 'N/A')

    """
    vuln_dict = {}
    vuln_dict["whitelist_source"] = row[0]
    vuln_dict["vulnerability"] = row[3]
    vuln_dict["vuln_source"] = row[4]
    vuln_dict["status"] = row[6]
    vuln_dict["justification"] = row[8]
    vuln_dict["package"] = row[10]
    vuln_dict["package_path"] = row[11]
    return vuln_dict


def _get_complete_whitelist_for_image(image_name, whitelist_branch, hardening_manifest):
    """
    Pull all whitelisted CVEs for an image. Walk through the ancestry of a given
    image and grab all of the approved vulnerabilities in VAT associated with w layer.

    """
    total_whitelist = []
    inheritance_list = []

    # add source image to inheritance list
    inheritance_list.append((os.environ["IMAGE_NAME"], os.environ["IMAGE_VERSION"]))

    # add parent images to inheritance list
    parent_image_name, parent_image_version = _next_ancestor(
        image_path=image_name,
        whitelist_branch=whitelist_branch,
        hardening_manifest=hardening_manifest,
    )

    while parent_image_name:
        inheritance_list.append((parent_image_name, parent_image_version))
        parent_image_name, parent_image_version = _next_ancestor(
            image_path=parent_image_name,
            whitelist_branch=whitelist_branch,
        )

    logging.debug(inheritance_list)

    inheritance_list.reverse()
    # grabbing cves from vat in reverse order to prevent issues with findings that shouldn't be inherited
    for image in inheritance_list:
        logging.info(f"Grabbing CVEs for: {image[0]}:{image[1]}")
        result = _vat_vuln_query(image[0], image[1])
        if result is None:
            logging.error("No results from vat. Fatal error.")
            sys.exit(1)
        # parse CVEs from VAT query
        # empty list is returned if no entry or no cves. NoneType only returned if error.
        for row in result:
            logging.debug(row)
            vuln_dict = _get_vulns_from_query(row)
            if vuln_dict["status"] and vuln_dict["status"].lower() in [
                "approved",
                "conditional",
            ]:
                total_whitelist.append(vuln_dict)
                logging.debug(vuln_dict)
            else:
                logging.debug(
                    "There is no approval status present in result or cve not approved"
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
    compAnchore = {}

    # Getting results from VAT, just loop all findings, check if finding is related to base_images or source image
    # Loop through the findings and create the corresponding dict object based on the vuln_source
    for finding in total_whitelist:
        if "vulnerability" in finding.keys():
            trigger_id = finding["vulnerability"]
            # Twistlock finding
            if finding["vuln_source"] == "twistlock_cve":
                cveID = (finding["vulnerability"], finding["package"])
                if finding["whitelist_source"] == sourceImageName:
                    cveTwistlock[cveID] = finding["justification"]
                else:
                    cveTwistlock[cveID] = "Inherited from base image."
                    logging.debug("Twistlock inherited cve")

            # Anchore finding
            elif finding["vuln_source"] == "anchore_cve":
                cveID = (
                    finding["vulnerability"],
                    finding["package"],
                    finding["package_path"],
                )
                if finding["whitelist_source"] == sourceImageName:
                    cveAnchore[cveID] = finding["justification"]
                    cveAnchore[trigger_id] = finding["justification"]
                else:
                    logging.debug("Anchore inherited cve")
                    cveAnchore[cveID] = "Inherited from base image."
                    if trigger_id in _inheritable_trigger_ids:
                        cveAnchore[trigger_id] = "Inherited from base image."
            elif finding["vuln_source"] == "anchore_comp":
                cveID = finding["vulnerability"]
                if finding["whitelist_source"] == sourceImageName:
                    compAnchore[cveID] = finding["justification"]
                    compAnchore[trigger_id] = finding["justification"]
                else:
                    logging.debug("Anchore Comp inherited finding")
                    compAnchore[cveID] = "Inherited from base image."
                    if trigger_id in _inheritable_trigger_ids:
                        compAnchore[trigger_id] = "Inherited from base image."

            # OpenSCAP finding
            elif finding["vuln_source"] == "oscap_comp":
                cveID = finding["vulnerability"]
                if finding["whitelist_source"] == sourceImageName:
                    cveOpenscap[cveID] = finding["justification"]
                else:
                    cveOpenscap[cveID] = "Inherited from base image."
                    logging.debug("Oscap inherited cve")
            logging.debug(f"VAT CVE ID: {cveID}")
    return cveOpenscap, cveTwistlock, cveAnchore, compAnchore


# Blank OSCAP Report
def generate_blank_oscap_report(csv_dir):
    oscap_report = open(csv_dir + "oscap.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(oscap_report)
    csv_writer.writerow(
        ["OpenSCAP Scan Skipped Due to Base Image Used", "", "", "", "", "", "", "", ""]
    )
    oscap_report.close()


# Blank oval Report
def generate_blank_oval_report(csv_dir):
    oval_report = open(csv_dir + "oval.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(oval_report)
    csv_writer.writerow(
        ["OpenSCAP Scan Skipped Due to Base Image Used", "", "", "", ""]
    )
    oval_report.close()


# SUMMARY REPORT
def generate_summary_report(
    csv_dir, osc, ovf, tlf, anchore_num_cves, anchore_compliance
):
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
    anchore_vulns = ["Anchore CVE Results", anchore_num_cves, 0, anchore_num_cves]
    anchore_comps = [
        "Anchore Compliance Results",
        anchore_compliance["stop_count"],
        0,
        anchore_compliance["stop_count"],
    ]
    twl = ["Twistlock Vulnerability Results", int(tlf or 0), 0, int(tlf or 0)]

    csv_writer.writerow(header)
    csv_writer.writerow(osl)
    csv_writer.writerow(ovf)
    csv_writer.writerow(twl)
    csv_writer.writerow(anchore_vulns)
    csv_writer.writerow(anchore_comps)
    csv_writer.writerow(
        [
            "Totals",
            osl[1] + ovf[1] + anchore_vulns[1] + anchore_comps[1] + twl[1],
            osl[2] + ovf[2] + anchore_vulns[2] + anchore_comps[2] + twl[2],
            osl[3] + ovf[3] + anchore_vulns[3] + anchore_comps[3] + twl[3],
        ]
    )

    csv_writer.writerow("")
    # date_str = 'Scans performed on: ' + str(osc[2])
    # csv_writer.writerow(['Scans performed on:', ]) # need date scanned
    sha_str = f"Scans performed on container layer sha256: {anchore_compliance['image_id']},,,"
    csv_writer.writerow([sha_str])
    sum_data.close()


# Generate csv for OSCAP findings with justifications
def generate_oscap_report(oscap, justifications, csv_dir):
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
            logging.error(f"problem writing line: {line.values()}")
            raise e
    oscap_data.close()
    return fail_count, nc_count, scanned

# Get full OSCAP report with justifications for csv export
def get_oscap_full(oscap_file, justifications):
    root = etree.parse(oscap_file)
    ns = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "xhtml": "http://www.w3.org/1999/xhtml", # not actually needed
        "dc": "http://purl.org/dc/elements/1.1/",
    }
    cces = []
    for rule_result in root.findall("xccdf:TestResult/xccdf:rule-result", ns):
        # Current CSV values
        # title,ruleid,result,severity,identifiers,refs,desc,rationale,scanned_date,Justification
        rule_id = rule_result.attrib['idref']
        severity = rule_result.attrib['severity']
        date_scanned = rule_result.attrib['time']
        result = rule_result.find("xccdf:result", ns).text

        # Get the <rule> that corresponds to the <rule-result>
        # This technically allows xpath injection, but we trust XCCDF files from OpenScap enough
        rule = root.find(f".//xccdf:Rule[@id='{rule_id}']", ns)
        title = rule.find("xccdf:title", ns).text

        # This is the identifier that VAT will use. It will never be unset.
        # Values will be of the format UBTU-18-010100 (UBI) or CCI-001234 (Ubuntu)
        # Ubuntu/DISA:
        identifiers = [v.text for v in rule.findall("xccdf:version", ns)]
        if not identifiers:
            # UBI/ComplianceAsCode:
            identifiers = [i.text for i in rule.findall("xccdf:ident", ns)]
        # We never expect to get more than one identifier
        if len(identifiers) == 1:
            # DEBUG
            print(identifiers)
        assert len(identifiers) == 1
        identifier = identifiers[0]
        # Revisit this if we ever switch UBI from ComplianceAsCode to DISA content

        def format_reference(ref):
            ref_title = ref.find(f"dc:title", ns)
            ref_identifier = ref.find(f"dc:identifier", ns)
            href = ref.attrib.get("href")
            if ref_title is not None:
                assert ref_identifier is not None
                return f"{ref_title.text}: {ref_identifier.text}"
            elif href:
                return f"{href} {ref.text}"

            return ref.text

        # This is now informational only, vat_import no longer uses this field
        references = "\n".join(format_reference(r) for r in rule.findall("xccdf:reference", ns))
        assert references

        rationale = ""
        rationale_element = rule.find("xccdf:rationale", ns)
        # Ubuntu XCCDF has no <rationale>
        if rationale_element:
            rationale = etree.tostring(rationale_element, method="text").strip()

        # Convert description to text, seems to work well:
        description = etree.tostring(rule.find("xccdf:description", ns), method="text").decode('utf8').strip()
        # Cleanup Ubuntu descriptions
        match = re.match(r'<VulnDiscussion>(.*)</VulnDiscussion>', description, re.DOTALL)
        if match:
            description = match.group(1)
 
        cve_justification = ""
        if identifier in justifications:
            cve_justification = justifications[identifier]

        if cve_justification != '' or result != 'notselected':
            ret = {
                "title": title,
                "ruleid": rule_id,
                "result": result,
                "severity": severity,
                "identifiers": identifier,
                "refs": references,
                "desc": description,
                "rationale": rationale,
                "scanned_date": date_scanned,
                "Justification": cve_justification,
            }
            cces.append(ret)
    print(cces)
    return cces


# Generate oval csv
def generate_oval_report(oval, csv_dir):
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
    # def get_packages(definition, root, ns):
    #     criterions = definition.findall(".//d:criterion[@test_ref]", ns)
    #     assert criterions
    #     for criterion in criterions:
    #         criterion_id = criterion.attrib['test_ref']
    #         lin_test = root.findall(f".//lin-def:rpmverifyfile_test[@id='{criterion_id}']", ns)
    #         lin_test += root.findall(f".//lin-def:dpkginfo_test[@id='{criterion_id}']", ns)
    #         assert len(lin_test) == 1
    #
    #         object_ref = lin_test[0].find("lin-def:object", ns).attrib["object_ref"]
    #
    #         # This only matches <lin-def:rpminfo_object>, other objects like <lin-def:rpmverifyfile_object> aren't matched
    #         lin_objects = root.findall(f".//lin-def:rpminfo_object[@id='{object_ref}']", ns)
    #         lin_objects = root.findall(f".//lin-def:dpkginfo_object[@id='{object_ref}']", ns)
    #         assert len(lin_objects) == 1
    #         lin_object = lin_objects[0]
    #
    #         lin_name = lin_object.find("lin-def:name", ns)
    #         if lin_name.text:
    #             yield lin_name.text
    #         else:
    #             var_ref = lin_name.attrib["var_ref"]
    #             constant_variable = root.find(f".//d:constant_variable[@id='{var_ref}']", ns)
    #             values = constant_variable.findall('d:value', ns)
    #             assert values
    #             for value in values:
    #                 yield value.text

    cves = []
    root = etree.parse(oval_file)
    tags = {elem.tag for elem in root.iter()}
    ns = {
        "r": "http://oval.mitre.org/XMLSchema/oval-results-5",
        "d": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
        "lin-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux",
    }
    for e in root.findall("r:results/r:system/r:definitions/r:definition", ns):
        definition_id = e.attrib['definition_id']
        result = e.attrib['result']

        definition = root.find(f".//d:definition[@id='{definition_id}']", ns)
        if definition.attrib["class"] != "vulnerability":
            break

        description = definition.find("d:metadata/d:description", ns).text
        title = definition.find("d:metadata/d:title", ns).text
        severity = definition.find("d:metadata/d:advisory/d:severity", ns).text
        references = [r.attrib.get('ref_id') for r in definition.findall("d:metadata/d:reference", ns)]
        assert references
        # packages = list(get_packages(definition, root, ns))
        # assert packages

        for ref in references:
            ret = {
                "id": definition_id,
                "result": result,
                "cls": description,
                "ref": ref,
                "title": title,
                # TODO: will adding columns break the XLSX generation?
                "severity": severity,
                # "packages": packages,
            }
            cves.append(ret)
    return cves

# Get results from Twistlock report for csv export
def generate_twistlock_report(twistlock_cve_json, justifications, csv_dir):
    with open(twistlock_cve_json, mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
        cves = []
        if json_data[0]["vulnerabilities"]:
            for d in json_data[0]["vulnerabilities"]:
                # get associated justification if one exists
                cve_justification = ""
                # if d["description"]:
                id = (d["cve"], f"{d['packageName']}-{d['packageVersion']}")
                # id = d["cve"] + "-" + d["description"]
                # else:
                #     id = d["cve"]
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

    write_csv_from_dict_list(
        dict_list=cves, fieldnames=fieldnames, filename="tl.csv", csv_dir=csv_dir
    )

    return len(cves)


if __name__ == "__main__":
    main()  # with if
