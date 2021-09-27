#!/usr/bin/env python3

import sys
import json
import os
import argparse
import logging
from pathlib import Path
import xml.etree.ElementTree as etree
import requests
from requests.structures import CaseInsensitiveDict


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
    "-j",
    "--job_id",
    help="Pipeline job ID",
    required=True,
)
parser.add_argument(
    "-sd",
    "--scan_date",
    help="Scan date for pipeline run",
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
    "-tl",
    "--twistlock",
    help="location of the twistlock JSON scan file",
    required=True,
)
parser.add_argument(
    "-oc",
    "--oscap",
    help="location of the oscap scan XML file",
    required=False,
)
parser.add_argument(
    "-ac",
    "--anchore-sec",
    help="location of the anchore_security.json scan file",
    required=True,
)
parser.add_argument(
    "-ag",
    "--anchore-gates",
    help="location of the anchore_gates.json scan file",
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
    "-uj",
    "--use_json",
    help="Dump payload for API to out.json file",
    action="store_true",
    required=False,
)


def _format_reference(ref, n_set):
    ref_title = ref.find("dc:title", n_set)
    ref_identifier = ref.find("dc:identifier", n_set)
    if ref_title is not None:
        assert ref_identifier is not None
        return f"{ref_title.text}: {ref_identifier.text}"
    return ref.text


# Get full OSCAP report with justifications for csv export
def generate_oscap_jobs(oscap_path):
    oc_path = Path(oscap_path)

    root = etree.parse(oc_path)
    n_set = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "xhtml": "http://www.w3.org/1999/xhtml",  # not actually needed
        "dc": "http://purl.org/dc/elements/1.1/",
    }

    patches_up_to_date_dupe = False
    cces = []
    for rule_result in root.findall("xccdf:TestResult/xccdf:rule-result", n_set):
        rule_id = rule_result.attrib["idref"]
        severity = rule_result.attrib["severity"]
        result = rule_result.find("xccdf:result", n_set).text
        logging.debug("Rule ID: %s", rule_id)
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
            patches_up_to_date_dupe = True

        # Get the <rule> that corresponds to the <rule-result>
        # This technically allows xpath injection, but we trust XCCDF files from OpenScap enough
        rule = root.find(f".//xccdf:Rule[@id='{rule_id}']", n_set)
        title = rule.find("xccdf:title", n_set).text

        # This is the identifier that VAT will use. It will never be unset.
        # Values will be of the format UBTU-18-010100 (UBI) or CCI-001234 (Ubuntu)
        # Ubuntu/DISA:
        identifiers = [ver.text for ver in rule.findall("xccdf:version", n_set)]
        if not identifiers:
            # UBI/ComplianceAsCode:
            identifiers = [ident.text for ident in rule.findall("xccdf:ident", n_set)]

        # We never expect to get more than one identifier
        assert len(identifiers) == 1
        logging.debug("Identifiers %s", identifiers)
        identifier = identifiers[0]
        # Revisit this if we ever switch UBI from ComplianceAsCode to DISA content

        # This is now informational only, vat_import no longer uses this field
        references = "\n".join(
            _format_reference(r_l, n_set)
            for r_l in rule.findall("xccdf:reference", n_set)
        )
        assert references

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
        assert len(set(cce["finding"] for cce in cces)) == len(cces)
    except Exception as duplicate_idents:
        for cce in cces:
            logging.info("Duplicate: %s", cce["finding"])
        raise duplicate_idents

    return cces


def generate_anchore_cve_jobs(anchore_sec_path):
    """
    Generate the anchore vulnerability report

    sorted_fix and fix_version_re needed for sorting fix string
    in case of duplicate cves with different sorts for the list of fix versions
    """
    as_path = Path(anchore_sec_path)
    with as_path.open(mode="r", encoding="utf-8") as f:
        json_data = json.load(f)

    cves = []
    for v_d in json_data["vulnerabilities"]:
        try:
            description = v_d["extra"]["description"]
        except KeyError:
            logging.info("Vulnerability description does not exist")
            description = "none"

        link_string = (
            "".join((item["source"] + ": " + item["url"] + "\n") for item in v_d["url"])
            if isinstance(v_d["url"], list)
            else v_d["url"]
        )
        cve = {
            "finding": v_d["vuln"],
            "severity": v_d["severity"].lower(),
            "description": description,
            "link": link_string,
            "score": "",
            "package": v_d["package"],
            "packagePath": v_d["package_path"]
            if v_d["package_path"] != "pkgdb"
            else None,
            "scanSource": "anchore_cve",
        }
        if cve not in cves:
            cves.append(cve)

    return cves


def generate_anchore_comp_jobs(anchore_comp_path):
    """
    Get results of Anchore gates for csv export, becomes anchore compliance spreadsheet
    """
    ac_path = Path(anchore_comp_path)
    with ac_path.open(mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
    sha = list(json_data.keys())[0]
    anchore_data_set = json_data[sha]["result"]["rows"]

    gates = []
    acomps = []
    for anchore_data in anchore_data_set:
        gate = {
            "image_id": anchore_data[0],
            "repo_tag": anchore_data[1],
            "trigger_id": anchore_data[2],
            "gate": anchore_data[3],
            "trigger": anchore_data[4],
            "check_output": anchore_data[5],
            "gate_action": anchore_data[6],
            "policy_id": anchore_data[8],
        }

        if anchore_data[7]:
            gate["matched_rule_id"] = anchore_data[7]["matched_rule_id"]
            gate["whitelist_id"] = anchore_data[7]["whitelist_id"]
            gate["whitelist_name"] = anchore_data[7]["whitelist_name"]
        else:
            gate["matched_rule_id"] = ""
            gate["whitelist_id"] = ""
            gate["whitelist_name"] = ""

        try:
            gate["inherited"] = anchore_data[9]
            if gate["gate"] == "dockerfile":
                gate["inherited"] = False
        except IndexError:
            gate["inherited"] = "no_data"

        gates.append(gate)

        desc_string = gate["check_output"] + "\n Gate: " + gate["gate"]
        desc_string = desc_string + "\n Trigger: " + gate["trigger"]
        desc_string = desc_string + "\n Policy ID: " + gate["policy_id"]
        if gate["gate"] != "vulnerabilities":
            vuln_rec = {
                "finding": gate["trigger_id"],
                "severity": "ga_" + gate["gate_action"],
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
def generate_twistlock_jobs(twistlock_cve_path):
    tc_path = Path(twistlock_cve_path)
    with tc_path.open(mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
    cves = []
    if json_data[0]["vulnerabilities"]:
        for v_d in json_data[0]["vulnerabilities"]:
            # get associated justification if one exists
            cves.append(
                {
                    "finding": v_d["cve"],
                    "severity": v_d["severity"].lower(),
                    "description": v_d["description"],
                    "link": v_d["link"],
                    "score": v_d["cvss"],
                    "package": v_d["packageName"] + "-" + v_d["packageVersion"],
                    "packagePath": None,
                    "scanSource": "twistlock_cve",
                }
            )
    return cves


def create_api_call():
    # get cves and justifications from VAT
    # Get all justifications
    logging.info("Gathering list of all justifications...")

    os_jobs = []
    tl_jobs = []
    asec_jobs = []
    acomp_jobs = []

    # if the DISTROLESS variable exists, the oscap job was not run.
    # When not os.environ.get("DISTROLESS"), this means this is not a DISTROLESS project, and oscap findings should be imported
    if args.oscap and not os.environ.get("DISTROLESS"):
        logging.debug("Importing oscap findings")
        os_jobs = generate_oscap_jobs(args.oscap)
        logging.debug(f"oscap finding count: {len(os_jobs)}")
    if args.anchore_sec:
        logging.debug("Importing anchore security findings")
        asec_jobs = generate_anchore_cve_jobs(args.anchore_sec)
        logging.debug(f"Anchore security finding count: {len(asec_jobs)}")
    if args.anchore_gates:
        logging.debug("Importing importing anchore compliance findings")
        acomp_jobs = generate_anchore_comp_jobs(args.anchore_gates)
        logging.debug(f"Anchore compliance finding count: {len(acomp_jobs)}")
    if args.twistlock:
        logging.debug("Importing twistlock findings")
        tl_jobs = generate_twistlock_jobs(args.twistlock)
        logging.debug(f"Twistlock finding count: {len(tl_jobs)}")
    all_jobs = tl_jobs + asec_jobs + acomp_jobs + os_jobs
    large_data = {
        "imageName": args.container,
        "imageTag": args.version,
        "parentImageName": args.parent,
        "parentImageTag": args.parent_version,
        "jobId": args.job_id,
        "digest": args.digest.replace("sha256:", ""),
        "timestamp": args.scan_date,
        "repo": {
            "url": args.repo_link,
            "commit": args.commit_hash,
        },
        "findings": all_jobs,
    }
    logging.debug(large_data)
    return large_data


def main():
    if not args.use_json:
        large_data = create_api_call()
        with open(f"{os.environ['ARTIFACT_STORAGE']}/vat_request.json", "w") as outfile:
            json.dump(large_data, outfile)
    else:
        with open(
            f"{os.environ['ARTIFACT_STORAGE']}/vat_request.json", encoding="utf-8"
        ) as o_f:
            large_data = json.loads(o_f.read())

    headers = CaseInsensitiveDict()
    headers["Content-Type"] = "application/json"
    headers["Authorization"] = f"Bearer {os.environ['CI_JOB_JWT']}"
    try:
        resp = requests.post(args.api_url, headers=headers, json=large_data)
        resp.raise_for_status()
        logging.info(f"API Response:\n{resp.text}")
        logging.info(f"POST Response: {resp.status_code}")
        with open(
            f"{os.environ['ARTIFACT_STORAGE']}/vat_response.json", "w"
        ) as outfile:
            json.dump(resp.json(), outfile)
    except RuntimeError:
        logging.exception("RuntimeError: API Call Failed")
        sys.exit(1)
    except requests.exceptions.HTTPError:
        logging.error(f"Got HTTP {resp.status_code}")
        logging.exception("HTTP error")
        sys.exit(1)
    except requests.exceptions.RequestException:
        logging.exception("Error submitting data to VAT scan import API")
        sys.exit(1)
    except Exception:
        logging.exception("Exception: Unknown exception")
        sys.exit(1)


if __name__ == "__main__":
    args = parser.parse_args()
    # Get logging level, set manually when running pipeline
    loglevel = os.environ.get("LOGLEVEL", "INFO").upper()
    if loglevel == "DEBUG":
        logging.basicConfig(
            level=loglevel,
            filename="new_vat_import_logging.out",
            format="%(levelname)s [%(filename)s:%(lineno)d]: %(message)s",
        )
        logging.debug("Log level set to debug")
    else:
        logging.basicConfig(level=loglevel, format="%(levelname)s: %(message)s")
        logging.info("Log level set to info")
    main()
