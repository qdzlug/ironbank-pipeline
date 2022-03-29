#!/usr/bin/env python3

import sys
import json
import os
import argparse
import logging
from pathlib import Path
import requests
from requests.structures import CaseInsensitiveDict

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)

from get_oscap_failures import generate_oscap_jobs  # noqa E402
from hardening_manifest import (
    source_values,
    get_source_keys_values,
)  # noqa E402

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
            logging.info(f"Vulnerability description does not exist for {v_d['vuln']}")
            description = "none"

        link_string = ""
        # check to make sure the vulnerability's url value is a list
        if isinstance(v_d["url"], list):
            for url in v_d["url"]:
                url_text = f"{url['source']}:{url['url']}\n"
                # Check to make sure that adding the current url to the link_string will not overflow the DB's column limit
                # If this value isn't checked and it is too large, the VAT API post will fail with a 500 error
                if len(url_text) + len(link_string) < 65535:
                    link_string += url_text
                else:
                    logging.warning(
                        "Unable to add all reference URLs to API POST. Please refer to anchore_security.json for more info."
                    )
                    break
        # vulnerability's url value is NOT a list. Just use the string value provided
        else:
            link_string = v_d["url"]
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
    if "vulnerabilities" in json_data["results"][0]:
        for v_d in json_data["results"][0]["vulnerabilities"]:
            # get associated justification if one exists
            try:
                cves.append(
                    {
                        "finding": v_d["id"],
                        "severity": v_d["severity"].lower(),
                        "description": v_d.get("description"),
                        "link": v_d.get("link"),
                        "score": v_d.get("cvss"),
                        "package": v_d["packageName"] + "-" + v_d["packageVersion"],
                        "packagePath": None,
                        "scanSource": "twistlock_cve",
                        "reportDate": v_d.get("publishedDate"),
                    }
                )
            except KeyError as e:
                logging.error(
                    "Missing key. Please contact the Iron Bank Pipeline and Ops (POPs) team"
                )
                logging.error(e.args)
                sys.exit(1)
    return cves


def create_api_call():
    artifact_storage = os.environ["ARTIFACT_STORAGE"]
    keyword_list = source_values(
        f"{artifact_storage}/preflight/keywords.txt", "keywords"
    )
    tag_list = source_values(f"{artifact_storage}/preflight/tags.txt", "tags")
    label_dict = get_source_keys_values(f"{artifact_storage}/preflight/labels.env")
    # get cves and justifications from VAT
    # Get all justifications
    logging.info("Gathering list of all justifications...")

    renovate_enabled = Path("renovate.json").is_file()

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
        "keywords": keyword_list,
        "tags": tag_list,
        "labels": label_dict,
        "renovateEnabled": renovate_enabled,
    }
    logging.debug(large_data)
    return large_data


def main():
    if not args.use_json:
        large_data = create_api_call()
        with open(f"{os.environ['ARTIFACT_DIR']}/vat_request.json", "w") as outfile:
            json.dump(large_data, outfile)
    else:
        with open(
            f"{os.environ['ARTIFACT_DIR']}/vat_request.json", encoding="utf-8"
        ) as o_f:
            large_data = json.loads(o_f.read())

    headers = CaseInsensitiveDict()
    headers["Content-Type"] = "application/json"
    headers["Authorization"] = f"Bearer {os.environ['CI_JOB_JWT']}"
    try:
        resp = requests.post(args.api_url, headers=headers, json=large_data)
        resp.raise_for_status()
        logging.debug(f"API Response:\n{resp.text}")
        logging.debug(f"POST Response: {resp.status_code}")
        with open(f"{os.environ['ARTIFACT_DIR']}/vat_response.json", "w") as outfile:
            json.dump(resp.json(), outfile)
    except RuntimeError:
        logging.exception("RuntimeError: API Call Failed")
        sys.exit(1)
    except requests.exceptions.HTTPError:
        # only include errors provided by VAT endpoint
        if resp.text and resp.status_code != 500:
            logging.error(f"API Response:\n{resp.text}")
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
            filename="vat_import_logging.out",
            format="%(levelname)s [%(filename)s:%(lineno)d]: %(message)s",
        )
        logging.debug("Log level set to debug")
    else:
        logging.basicConfig(level=loglevel, format="%(levelname)s: %(message)s")
        logging.info("Log level set to info")
    main()
