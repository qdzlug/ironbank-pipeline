#!/usr/bin/env python3

import sys
import re
import json
import os
import argparse
import pathlib
import logging
import xml.etree.ElementTree as etree

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

_uninheritable_trigger_ids = [
    "41cb7cdf04850e33a11f80c42bf660b3",
    "cbff271f45d32e78dcc1979dbca9c14d",
    "db0e0618d692b953341be18b99a2865a",
]

parser = argparse.ArgumentParser(
    description="DCCSCR processing of CVE reports from various sources"
)
parser.add_argument(
    "-a",
    "--api_url",
    help="Url for API POST",
    default="http://localhost:4000/internal/import/scan",
    required=False,
)
parser.add_argument(
    "-f",
    "--csv_dir",
    help="Path to Directory to all CSV files to parse",
    required=True,
)
parser.add_argument(
    "-j",
    "--job_id",
    help="Pipeline job ID",
    required=True,
)
parser.add_argument(
    "-sd",
    "--scan_date",
    help="scan_date for Jenkins run",
    required=True,
)
parser.add_argument(
    "-ch",
    "--commit_hash",
    help="Commit hash for container build",
    required=True,
)
parser.add_argument(
    "-c",
    "--container",
    help="Container VENDOR/PRODUCT/CONTAINER",
    required=True,
)
parser.add_argument(
    "-v",
    "--version",
    help="Container Version from VENDOR/PRODUCT/CONTAINER/VERSION format",
    required=True,
)
parser.add_argument(
    "-dg",
    "--digest",
    help="Container Digest as SHA256 Hash",
    required=True,
)
parser.add_argument(
    "-pc",
    "--parent",
    help="Parent VENDOR/PRODUCT/CONTAINER",
    required=False,
)
parser.add_argument(
    "-pv",
    "--parent_version",
    help="Parent Version from VENDOR/PRODUCT/CONTAINER/VERSION format",
    required=False,
)
parser.add_argument(
    "-cl",
    "--comp_link",
    help="Link to openscap compliance reports directory",
    required=True,
)
parser.add_argument(
    "-rl",
    "--repo_link",
    help="Link to container repository",
    default="",
    required=False,
)
parser.add_argument(
    "-dj",
    "--dump_json",
    help="Dump payload for API to out.json file",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-of",
    "--out_file",
    help="File path for API payload to write to file",
    default="out.json",
    required=False,
)
parser.add_argument(
    "-tl", "--twistlock", help="location of the twistlock JSON scan file"
)
parser.add_argument("-oc", "--oscap", help="location of the oscap scan XML file")
parser.add_argument(
    "-ac", "--anchore-sec", help="location of the anchore_security.json scan file"
)
parser.add_argument(
    "-ag", "--anchore-gates", help="location of the anchore_gates.json scan file"
)

args = parser.parse_args()


def _construct_job_parts(finding_dicts, source):
    """
    Construct a list of JSON objects for API Call
    """
    retset = []
    for l_item in finding_tuples:
        temp = {
            "finding": l_item["finding"],
            "severity": l_item["severity"].lower(),
            "description": l_item["description"],
            "link": l_item["link"],
            "score": l_item["score"],
            "package": l_item["package"],
            "packagePath": l_item["package_path"],
            "scanSource": source,
        }
        retset.append(temp)
    logs.debug(f"dataframe: \n {finding_tuples}")
    return retset


def _get_complete_whitelist_for_image(vat_findings, status_list):
    """
    Pull all whitelisted CVEs for an image. Walk through the ancestry of a given
    image and grab all of the approved vulnerabilities in VAT associated with w layer.

    """
    logging.info("Generating whitelist for %s:%s", args.container, args.version)
    total_whitelist = []
    # loop through each image, starting from child through each parent, grandparent, etc.
    for image in vat_findings:
        # loop through each finding
        for finding in vat_findings[image]:
            # if finding is approved
            logging.debug(finding)
            if finding["finding_status"].lower() in status_list:
                # if finding is uninheritable (i.e. Dockerfile findings), exclude from whitelist
                if (
                    image != args.container
                    and finding["finding"] in _uninheritable_trigger_ids
                ):
                    logging.debug(
                        "Excluding finding %s for %s", finding["finding"], image
                    )
                    continue
                # add finding as dictionary object in list
                # if finding is inherited, set justification as 'Inherited from base image.'
                total_whitelist.append(
                    {
                        "scan_source": finding["scan_source"],
                        "cve_id": finding["finding"],
                        "package": finding["package"],
                        "package_path": finding["package_path"],
                        "justification": finding["justification"]
                        if image == args.container
                        else "Inherited from base image.",
                    }
                )
    logging.info("Found %d total whitelisted CVEs", len(total_whitelist))
    return total_whitelist


def _split_by_scan_source(total_whitelist):
    """
    Gather all justifications for any approved CVE for anchore, twistlock and openscap.
    Keys are in the form (cve_id, package, package_name) for anchore_cve,
    (cve_id, package) for twistlock,
    or "cve_id" for anchore_comp and openscap.

    Examples:
        (CVE-2020-13434, sqlite-libs-3.26.0-11.el8, None) (anchore cve key)
        (CVE-2020-8285, sqlite-libs-3.26.0-11.el8) (twistlock key, truncated)
        CCE-82315-3 (openscap or anchore comp key)

    """
    cve_openscap = {}
    cve_twistlock = {}
    cve_anchore = {}
    comp_anchore = {}

    # Using results from VAT, loop all findings
    # Loop through the findings and create the corresponding dict object based on the vuln_source
    for finding in total_whitelist:
        if "cve_id" in finding.keys():
            # id used to search for justification when generating each scan's csv
            search_id = (
                finding["cve_id"],
                finding["package"],
                finding["package_path"],
            )
            logging.debug(search_id)
            if finding["scan_source"] == "oscap_comp":
                # only use cve_id
                cve_openscap[search_id[0]] = finding["justification"]
            elif finding["scan_source"] == "twistlock_cve":
                # use cve_id and package
                cve_twistlock[search_id[0:2]] = finding["justification"]
            elif finding["scan_source"] == "anchore_cve":
                # use full tuple
                cve_anchore[search_id] = finding["justification"]
            elif finding["scan_source"] == "anchore_comp":
                # only use cve_id
                comp_anchore[search_id[0]] = finding["justification"]

    return cve_openscap, cve_twistlock, cve_anchore, comp_anchore


# Get full OSCAP report with justifications for csv export
def generate_oscap_jobs(oscap_file, justifications):
    root = etree.parse(oscap_file)
    ns = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "xhtml": "http://www.w3.org/1999/xhtml",  # not actually needed
        "dc": "http://purl.org/dc/elements/1.1/",
    }
    patches_up_to_date_dupe = False
    cces = []
    for rule_result in root.findall("xccdf:TestResult/xccdf:rule-result", ns):
        # Current CSV values
        # title,ruleid,result,severity,identifiers,refs,desc,rationale,scanned_date,Justification
        rule_id = rule_result.attrib["idref"]
        severity = rule_result.attrib["severity"]
        date_scanned = rule_result.attrib["time"]
        result = rule_result.find("xccdf:result", ns).text
        logging.debug(rule_id)
        if result == "notselected":
            logging.debug("SKIPPING: 'notselected' rule %s", rule_id)
            continue

        if rule_id == "xccdf_org.ssgproject.content_rule_security_patches_up_to_date":
            if patches_up_to_date_dupe:
                logging.debug(
                    "SKIPPING: rule %s - OVAL check repeats and this finding is checked elsewhere",
                    rule_id,
                )
                continue
            else:
                patches_up_to_date_dupe = True
        # Get the <rule> that corresponds to the <rule-result>
        # This technically allows xpath injection, but we trust XCCDF files from OpenScap enough
        rule = root.find(".//xccdf:Rule[@id='%s']", rule_id)
        title = rule.find("xccdf:title", ns).text

        # This is the identifier that VAT will use. It will never be unset.
        # Values will be of the format UBTU-18-010100 (UBI) or CCI-001234 (Ubuntu)
        # Ubuntu/DISA:
        identifiers = [v.text for v in rule.findall("xccdf:version", ns)]
        if not identifiers:
            # UBI/ComplianceAsCode:
            identifiers = [i.text for i in rule.findall("xccdf:ident", ns)]
        # We never expect to get more than one identifier
        assert len(identifiers) == 1
        logging.debug(identifiers)
        identifier = identifiers[0]
        # Revisit this if we ever switch UBI from ComplianceAsCode to DISA content

        def format_reference(ref):
            ref_title = ref.find("dc:title", ns)
            ref_identifier = ref.find("dc:identifier", ns)
            href = ref.attrib.get("href")
            if ref_title is not None:
                assert ref_identifier is not None
                return f"{ref_title.text}: {ref_identifier.text}"
            return ref.text

        # This is now informational only, vat_import no longer uses this field
        references = "\n".join(
            format_reference(r) for r in rule.findall("xccdf:reference", ns)
        )
        assert references

        rationale_element = rule.find("xccdf:rationale", ns)
        # Ubuntu XCCDF has no <rationale>
        rationale = (
            etree.tostring(rationale_element, method="text").decode("utf-8").strip()
            if rationale_element is not None
            else ""
        )

        # Convert description to text, seems to work well:
        description = (
            etree.tostring(rule.find("xccdf:description", ns), method="text")
            .decode("utf8")
            .strip()
        )
        # Cleanup Ubuntu descriptions
        match = re.match(
            r"<VulnDiscussion>(.*)</VulnDiscussion>", description, re.DOTALL
        )
        if match:
            description = match.group(1)

        cve_justification = ""
        if identifier in justifications:
            cve_justification = justifications[identifier]
        if (result == "fail") | (result == "notchecked") | (result == "error"):
            ret = {
                "finding": identifier,
                "severity": severity.lower(),
                "description": title,
                "link": None,
                "score": "",
                "package": None,
                "packagePath": None,
                "scanSource": "oscap_comp",
            }
            cces.append(ret)
    try:
        assert len(set(cce["identifiers"] for cce in cces)) == len(cces)
    except Exception as duplicate_idents:
        for cce in cces:
            logger.info(cce["ruleid"], cce["identifiers"])
        raise duplicate_idents

    return cces


def _vulnerability_record(fulltag, justifications, vuln):
    """
    Create an individual vulnerability record
    sorted_fix and fix_version_re needed for sorting fix string in case of duplicate cves with different sorts for the list of fix versions
    """
    fix_version_re = "([A-Za-z0-9][-.0-~]*)"
    sorted_fix = re.findall(fix_version_re, vuln["fix"])
    sorted_fix.sort()

    vuln_record = dict()
    vuln_record["tag"] = fulltag
    vuln_record["cve"] = vuln["vuln"]
    vuln_record["severity"] = vuln["severity"]
    vuln_record["feed"] = vuln["feed"]
    vuln_record["feed_group"] = vuln["feed_group"]
    vuln_record["package"] = vuln["package"]
    vuln_record["package_path"] = vuln["package_path"]
    vuln_record["package_type"] = vuln["package_type"]
    vuln_record["package_version"] = vuln["package_version"]
    vuln_record["fix"] = ", ".join(sorted_fix)
    vuln_record["url"] = vuln["url"]
    vuln_record["inherited"] = vuln.get("inherited_from_base") or "no_data"

    try:
        vuln_record["description"] = vuln["extra"]["description"]
    except Exception:
        vuln_record["description"] = "none"

    key = "nvd_cvss_v2_vector"
    vuln_record[key] = ""
    try:
        vuln_record[key] = vuln["extra"]["nvd_data"][0]["cvss_v2"]["vector_string"]
    except Exception:
        logging.debug("no %s", key)

    key = "nvd_cvss_v3_vector"
    vuln_record[key] = ""
    try:
        vuln_record[key] = vuln["extra"]["nvd_data"][0]["cvss_v3"]["vector_string"]
    except Exception:
        logging.debug("no %s", key)

    key = "vendor_cvss_v2_vector"
    vuln_record[key] = ""
    try:
        for d in vuln["extra"]["vendor_data"]:
            if d["cvss_v2"] and d["cvss_v2"]["vector_string"]:
                vuln_record[key] = d["cvss_v2"]["vector_string"]
    except Exception:
        logging.debug("no %s", key)

    key = "vendor_cvss_v3_vector"
    vuln_record[key] = ""
    try:
        for d in vuln["extra"]["vendor_data"]:
            if d["cvss_v3"] and d["cvss_v3"]["vector_string"]:
                vuln_record[key] = d["cvss_v3"]["vector_string"]
    except Exception:
        logging.debug("no %s", key)

    vuln_record["Justification"] = ""
    f_id = (
        vuln["vuln"],
        vuln["package"],
        vuln["package_path"] if vuln["package_path"] != "pkgdb" else None,
    )
    logging.debug("Anchore vuln record CVE ID: %s", f_id)
    if f_id in justifications.keys():
        vuln_record["Justification"] = justifications[f_id]

    source_list = ast.literal_eval(vuln_record["url"])
    link_string = "".join(
        (item["source"] + ": " + item["url"] + "\n") for item in source_list
    )
    vuln_rec = {
            "finding": vuln_record["cve"],
            "severity": vuln_record["severity"],
            "description": vuln_record["description"],
            "link": link_string,
            "score": "",
            "package": vuln_record["package"],
            "packagePath": vuln_record["package_path"],
            "scanSource": "anchore_cve",
        }

    return vuln_record


def generate_anchore_cve_jobs(anchore_security_json, justifications):
    """
    Generate the anchore vulnerability report

    """
    with open(anchore_security_json, mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
        cves = []
        for d in json_data["vulnerabilities"]:
            cve = _vulnerability_record(
                fulltag=json_data["imageFullTag"], justifications=justifications, vuln=d
            )
            if cve not in cves:
                cves.append(cve)

    return cves


def generate_anchore_comp_jobs(anchore_gates_json, justifications):
    """
    Get results of Anchore gates for csv export, becomes anchore compliance spreadsheet

    """
    with open(anchore_gates_json, encoding="utf-8") as f:
        json_data = json.load(f)
        sha = list(json_data.keys())[0]
        anchore_data = json_data[sha]["result"]["rows"]

    gates = []
    acomps = []
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
        pkg_id = ad[2]
        if ad[4] == "package":
            cve_justification = "See Anchore CVE Results sheet"

        if pkg_id in justifications.keys():
            cve_justification = justifications[pkg_id]
        gate["Justification"] = cve_justification

        gates.append(gate)

        image_id = gate["image_id"]

        desc_string = gate["check_output"] + "\n Gate: " + gate["gate"]
        desc_string = desc_string + "\n Trigger: " + gate["trigger"]
        desc_string = desc_string + "\n Policy ID: " + gate["policy_id"]
        if gate["gate"] != "vulnerabilities":
            vuln_rec = {
                "finding": gate["trigger_id"],
                "severity": "ga_" + gate["gate_action"].astype(str),
                "description": desc_string,
                "link": None,
                "score": "",
                "package": None,
                "packagePath": None,
                "scanSource": "anchore_comp",
            }
            acomps.append(vuln_rec)

    return acomps


# Get results from Twistlock report for finding generation
def generate_twistlock_jobs(twistlock_cve_json, justifications):
    with open(twistlock_cve_json, mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
        cves = []
    # twistlock = pandas.read_csv(tl_path)

    # # grab the relevant columns we are homogenizing
    # d_f = twistlock[
    #     ["id", "severity", "desc", "link", "cvss", "packageName", "packageVersion"]
    # ]
    # d_f.rename(
    #     columns={"id": "finding", "desc": "description", "cvss": "score"},
    #     inplace=True,
    # )

    # d_f["package"] = d_f["packageName"] + "-" + d_f["packageVersion"]
    # d_f.drop(columns=["packageName", "packageVersion"], inplace=True)

    # d_f = d_f.assign(package_path=None)

    # d_f_clean = d_f.where(pandas.notnull(d_f), None)

    # return construct_job_parts(d_f_clean.itertuples(), "twistlock_cve")
        if json_data[0]["vulnerabilities"]:
            for d in json_data[0]["vulnerabilities"]:
                # get associated justification if one exists
                cve_justification = ""

                pkg_id = (d["cve"], f"{d['packageName']}-{d['packageVersion']}")

                if pkg_id in justifications.keys():
                    cve_justification = justifications[pkg_id]
                cves.append(
                    {
                        "finding": d["cve"],
                        "score": d["cvss"],
                        "description": d["description"],
                        "link": d["link"],
                        "package": d["packageName"] + "-" + d["packageVersion"],
                        "packagePath": None,
                        "severity": d["severity"],
                    }
                )
        else:
            cves = []

    return cves


def main():
    artifacts_path = os.environ["ARTIFACT_STORAGE"]
    # get cves and justifications from VAT
    vat_findings_file = pathlib.Path(artifacts_path, "lint", "vat_findings.json")
    # load vat_findings.json file
    try:
        with vat_findings_file.open(mode="r") as f:
            vat_findings = json.load(f)
    except Exception:
        logging.exception("Error reading findings file.")
        sys.exit(1)

    approval_status_list = ["approved", "conditional"]
    total_whitelist = _get_complete_whitelist_for_image(
        vat_findings, approval_status_list
    )
    # Get all justifications
    logging.info("Gathering list of all justifications...")

    j_openscap, j_twistlock, j_anchore_cve, j_anchore_comp = _split_by_scan_source(
        total_whitelist
    )

    if args.oscap:
        generate_oscap_jobs(args.oscap, j_openscap)
    if args.twistlock:
        generate_twistlock_jobs(args.twistlock, j_twistlock)
    if args.anchore_sec:
        generate_anchore_cve_jobs(
            anchore_security_json=args.anchore_sec,
            justifications=j_anchore_cve,
        )
    if args.anchore_gates:
        generate_anchore_comp_jobs(
            anchore_gates_json=args.anchore_gates,
            justifications=j_anchore_comp,
        )


if __name__ == "__main__":
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
    main()
