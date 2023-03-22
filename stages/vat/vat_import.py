#!/usr/bin/env python3

import sys
import json
import os
import shutil
import logging
import argparse
from pathlib import Path
from itertools import groupby
import requests
from requests.structures import CaseInsensitiveDict

from ironbank.pipeline.image import Image
from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.container_tools.cosign import Cosign
from ironbank.pipeline.utils.predicates import Predicates
from ironbank.pipeline.scan_report_parsers.anchore import AnchoreSecurityParser
from ironbank.pipeline.get_oscap_failures import generate_oscap_jobs
from ironbank.pipeline.hardening_manifest import (
    HardeningManifest,
    source_values,
    get_source_keys_values,
)


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
    "-ts",
    "--timestamp",
    help="Timestamp for current pipeline run",
    required=True,
)
parser.add_argument(
    "-sd",
    "--scan_date",
    help="Scan date for pipeline run",
    required=True,
)
parser.add_argument(
    "-bd",
    "--build_date",
    help="Build date for pipeline run",
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

    with Path(anchore_sec_path).open(mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
    vulns = AnchoreSecurityParser.get_vulnerabilities(json_data)
    cves = []
    fieldnames = [
        "finding",
        "severity",
        "description",
        "link",
        "score",
        "package",
        "packagePath",
        "scanSource",
        "identifiers",
    ]

    for vuln in vulns:
        vuln.get_truncated_url()
        vuln.package_path = vuln.package_path if vuln.package_path != "pkgdb" else None
        vuln.severity = vuln.severity.lower()
        cve = {k: v for k, v in vuln.dict().items() if k in fieldnames}
        cve["score"] = ""
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
                # use old format for scan report parsing
                "scanSource": "anchore_comp",
            }
            acomps.append(vuln_rec)

    return acomps


def get_package_paths(twistlock_data):
    """
    Return a dict of (package_name, package_path) mapped to a list of paths.
    """

    def packages():
        # Often go versions of binaries are in "applications"
        yield from twistlock_data.get("applications", [])

        # Python/RPM/Go/etc package versions are in "packages"
        yield from twistlock_data.get("packages", [])

    # Sort and group by name and version
    keyfunc = lambda x: (x["name"], x["version"])  # noqa E731

    pkg_paths = {}
    sorted_pkgs = sorted(packages(), key=keyfunc)
    grouped_pkgs = groupby(sorted_pkgs, key=keyfunc)

    for k, pkgs in grouped_pkgs:
        path_set = {p.get("path", None) for p in pkgs}
        pkg_paths[k] = path_set

    return pkg_paths


def get_vulnerabilities(twistlock_data):
    """
    Convert the the Twistlock API JSON response to the VAT import format.
    """

    packages = get_package_paths(twistlock_data)

    try:
        for v in twistlock_data.get("vulnerabilities", []):
            key = v["packageName"], v["packageVersion"]
            severity = (
                "low"
                if v.get("severity").lower() == "unimportant"
                else v.get("severity").lower()
            )
            for path in packages.get(key, [None]):
                yield {
                    "finding": v["id"],
                    "severity": severity,
                    "description": v.get("description"),
                    "link": v.get("link"),
                    "score": v.get("cvss"),
                    "package": f"{v['packageName']}-{v['packageVersion']}",
                    "packagePath": path,
                    "scanSource": "twistlock_cve",
                    "reportDate": v.get("publishedDate"),
                    "identifiers": [v["id"]],
                }
    except KeyError as e:
        logging.error(
            "Missing key. Please contact the Iron Bank Pipeline and Ops (POPs) team"
        )
        logging.error(e.args)
        sys.exit(1)


# Get results from Twistlock report for finding generation
def generate_twistlock_jobs(twistlock_cve_path):
    tc_path = Path(twistlock_cve_path)
    with tc_path.open(mode="r", encoding="utf-8") as f:
        json_data = json.load(f)

    return list(get_vulnerabilities(json_data["results"][0]))


def create_api_call():
    artifact_storage = os.environ["ARTIFACT_STORAGE"]
    keyword_list = source_values(f"{artifact_storage}/lint/keywords.txt", "keywords")
    tag_list = source_values(f"{artifact_storage}/lint/tags.txt", "tags")
    label_dict = get_source_keys_values(f"{artifact_storage}/lint/labels.env")
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
        logging.debug("oscap finding count: %s", len(os_jobs))
    if args.anchore_sec:
        logging.debug("Importing anchore security findings")
        asec_jobs = generate_anchore_cve_jobs(args.anchore_sec)
        logging.debug("Anchore security finding count: %s", len(asec_jobs))
    if args.anchore_gates:
        logging.debug("Importing importing anchore compliance findings")
        acomp_jobs = generate_anchore_comp_jobs(args.anchore_gates)
        logging.debug("Anchore compliance finding count: %s", len(acomp_jobs))
    if args.twistlock:
        logging.debug("Importing twistlock findings")
        tl_jobs = generate_twistlock_jobs(args.twistlock)
        logging.debug("Twistlock finding count: %s", len(tl_jobs))
    all_jobs = tl_jobs + asec_jobs + acomp_jobs + os_jobs
    large_data = {
        "imageName": args.container,
        "imageTag": args.version,
        "parentImageName": args.parent,
        "parentImageTag": args.parent_version,
        "jobId": args.job_id,
        "digest": args.digest.replace("sha256:", ""),
        "timestamp": args.timestamp,
        "scanDate": args.scan_date,
        "buildDate": args.build_date,
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


def get_parent_vat_response(output_dir: str, hardening_manifest: HardeningManifest):
    base_image = Image(
        registry=os.environ["BASE_REGISTRY"],
        name=hardening_manifest.base_image_name,
        tag=hardening_manifest.base_image_tag,
    )
    vat_response_predicate = "https://vat.dso.mil/api/p1/predicate/beta1"
    pull_auth = Path(os.environ["DOCKER_AUTH_FILE_PULL"])
    docker_config_dir = Path("/tmp/docker_config")
    docker_config_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(src=pull_auth, dst=Path(docker_config_dir, "config.json"))
    Cosign.download(
        base_image,
        output_dir=output_dir,
        docker_config_dir=docker_config_dir,
        predicate_types=[vat_response_predicate],
    )
    predicates = Predicates()
    predicate_path = Path(
        output_dir, predicates.get_predicate_files()[vat_response_predicate]
    )
    parent_vat_path = Path(output_dir, "parent_vat_response.json")
    shutil.move(predicate_path, parent_vat_path)


def main():
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)

    if hardening_manifest.base_image_name:
        get_parent_vat_response(
            output_dir=os.environ["ARTIFACT_DIR"], hardening_manifest=hardening_manifest
        )
        parent_vat_path = Path(f"{os.environ['ARTIFACT_DIR']}/parent_vat_response.json")
        with parent_vat_path.open("r", encoding="UTF-8") as f:
            parent_vat_response_content = {"vatAttestationLineage": json.load(f)}
        logging.debug(parent_vat_response_content)
    else:
        parent_vat_response_content = {"vatAttestationLineage": None}

    vat_request_json = Path(f"{os.environ['ARTIFACT_DIR']}/vat_request.json")
    if not args.use_json:
        large_data = create_api_call()
        large_data.update(parent_vat_response_content)
        with vat_request_json.open("w", encoding="utf-8") as outfile:
            json.dump(large_data, outfile)
    else:
        with vat_request_json.open(encoding="utf-8") as infile:
            large_data = json.load(infile)

    headers = CaseInsensitiveDict()
    headers["Content-Type"] = "application/json"
    headers["Authorization"] = f"Bearer {os.environ['CI_JOB_JWT_V2']}"
    try:
        resp = requests.post(args.api_url, headers=headers, json=large_data)
        resp.raise_for_status()
        logging.debug("API Response:\n%s", resp.text)
        logging.debug("POST Response: %s", resp.status_code)
        with Path(f"{os.environ['ARTIFACT_DIR']}/vat_response.json").open(
            "w", encoding="utf-8"
        ) as outfile:
            json.dump(resp.json(), outfile)
    except RuntimeError:
        logging.exception("RuntimeError: API Call Failed")
        sys.exit(1)
    except requests.exceptions.HTTPError:
        # only include errors provided by VAT endpoint
        if resp.text and resp.status_code != 500:
            logging.error("API Response:\n%s", resp.text)
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
