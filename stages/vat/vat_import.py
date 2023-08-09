#!/usr/bin/env python3

import json
import os
import shutil
import sys
from itertools import groupby
from pathlib import Path
from typing import Any, Generator, Tuple
from common.utils import logger

import requests
from requests.structures import CaseInsensitiveDict

from pipeline.container_tools.cosign import Cosign
from pipeline.hardening_manifest import (
    HardeningManifest,
    get_source_keys_values,
    source_values,
)
from pipeline.image import Image
from pipeline.project import DsopProject
from pipeline.scan_report_parsers.anchore import AnchoreReportParser
from pipeline.scan_report_parsers.oscap import OscapReportParser
from pipeline.utils.predicates import Predicates

# from pipeline.utils.envutils import EnvUtil

from args import EnvUtil

log = logger.setup("vat_import")


def generate_anchore_cve_findings(
    report_path: Path, vat_finding_fields: list[str]
) -> list[dict[str, Any]]:
    """From an anchore cve finding report, generate findings and use list of
    findings and their metadata to generate list of dictionaries.

    sorted_fix and fix_version_re needed for sorting fix string in case
    of duplicate cves with different sorts for the list of fix versions
    """

    findings = AnchoreReportParser.get_findings(report_path=Path(report_path))

    formatted_findings = []
    for finding in findings:
        finding.set_truncated_url()
        finding.package_path = (
            finding.package_path if finding.package_path != "pkgdb" else None
        )
        finding.severity = finding.severity.lower()
        formatted_findings.append(
            {**finding.get_dict_from_fieldnames(vat_finding_fields), "score": ""}
        )

    return formatted_findings


def generate_oscap_findings(
    report_path: Path, vat_finding_fields: list[str]
) -> list[dict[str, Any]]:
    """From an oscap comp finding report, generate findings and use list of
    findings and their metadata to generate list of dictionaries."""
    return [
        finding.get_dict_from_fieldnames(vat_finding_fields)
        for finding in OscapReportParser.get_findings(report_path=Path(report_path))
    ]


def generate_anchore_comp_findings(anchore_comp_path: Path) -> list[dict[str, Any]]:
    """From an anchore comp finding report, generate findings and use list of
    findings and their metadata to generate list of dictionaries."""
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


def get_twistlock_package_paths(twistlock_data: dict[str, Any]) -> dict:
    """Return a dict of (package_name, package_path) mapped to a list of
    paths."""

    def packages() -> Generator[Any, None, None]:
        # Often go versions of binaries are in "applications"
        yield from twistlock_data.get("applications", [])

        # Python/RPM/Go/etc package versions are in "packages"
        yield from twistlock_data.get("packages", [])

    def keyfunc(key: Any) -> Tuple[str, str]:
        return key["name"], key["version"]

    # Sort and group by name and version
    # keyfunc = lambda x: (x["name"], x["version"])  # noqa E731

    pkg_paths = {}
    sorted_pkgs = sorted(packages(), key=keyfunc)
    grouped_pkgs = groupby(sorted_pkgs, key=keyfunc)

    for k, pkgs in grouped_pkgs:
        path_set = {p.get("path", None) for p in pkgs}
        pkg_paths[k] = path_set

    return pkg_paths


# Get results from Twistlock report for finding generation
def generate_twistlock_findings(twistlock_cve_path: Path) -> list[dict[str, Any]]:
    """From an twistlock cve finding report, generate findings and use list of
    findings and their metadata to generate list of dictionaries."""
    twistlock_data = json.loads(Path(twistlock_cve_path).read_text(encoding="utf-8"))[
        "results"
    ][0]

    packages = get_twistlock_package_paths(twistlock_data)

    findings = []
    try:
        for value in twistlock_data.get("vulnerabilities", []):
            key = value["packageName"], value["packageVersion"]
            severity = (
                "low"
                if value.get("severity").lower() == "unimportant"
                else value.get("severity").lower()
            )
            for path in packages.get(key, [None]):
                findings.append(
                    {
                        "finding": value["id"],
                        "severity": severity,
                        "description": value.get("description"),
                        "link": value.get("link"),
                        "score": value.get("cvss"),
                        "package": f"{value['packageName']}-{value['packageVersion']}",
                        "packagePath": path,
                        "scanSource": "twistlock_cve",
                        "reportDate": value.get("publishedDate"),
                        "identifiers": [value["id"]],
                    }
                )
    except KeyError as e:
        log.error(
            "Missing key. Please contact the Iron Bank Pipeline and Ops (POPs) team"
        )
        log.error(e.args)
        sys.exit(1)

    return findings


def create_api_call() -> dict:
    """Creates the data for an API call based on various environmental
    variables and findings.

    This function gathers keyword, tag, label data from a predefined storage location.
    Then it imports the findings from different scanning tools if their specific arguments
    are provided. Finally, all this data is assembled into a dictionary.

    Environment Variables:
    - ARTIFACT_STORAGE: The storage location for keywords, tags, and label data.
    - VAT_FINDING_FIELDS: (Optional) The fields to be included in the findings from VAT.
                          Defaults to a predefined list of fields.
    - IMAGE_TO_SCAN: The image to be scanned.

    Returns:
    - large_data: The dictionary containing all the assembled data.
    """
    artifact_storage = os.environ["ARTIFACT_STORAGE"]
    keyword_list = source_values(f"{artifact_storage}/lint/keywords.txt", "keywords")
    tag_list = source_values(f"{artifact_storage}/lint/tags.txt", "tags")
    label_dict = get_source_keys_values(f"{artifact_storage}/lint/labels.env")
    # get cves and justifications from VAT
    # Get all justifications
    log.info("Gathering list of all justifications...")

    renovate_enabled = Path("renovate.json").is_file()

    os_findings = []
    tl_findings = []
    asec_findings = []
    acomp_findings = []

    vat_finding_fields = os.environ.get("VAT_FINDING_FIELDS") or [
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
    assert isinstance(vat_finding_fields, list)

    # if the SKIP_OPENSCAP variable exists, the oscap job was not run.
    # When not os.environ.get("SKIP_OPENSCAP"), this means this is not a SKIP_OPENSCAP project, and oscap findings should be imported
    if args.oscap and not os.environ.get("SKIP_OPENSCAP"):
        log.debug("Importing oscap findings")
        os_findings = generate_oscap_findings(
            args.oscap, vat_finding_fields=vat_finding_fields
        )
        log.debug("oscap finding count: %s", len(os_findings))
    if args.anchore_sec:
        log.debug("Importing anchore security findings")
        asec_findings = generate_anchore_cve_findings(
            args.anchore_sec, vat_finding_fields=vat_finding_fields
        )
        log.debug("Anchore security finding count: %s", len(asec_findings))
    if args.anchore_gates:
        log.debug("Importing importing anchore compliance findings")
        acomp_findings = generate_anchore_comp_findings(args.anchore_gates)
        log.debug("Anchore compliance finding count: %s", len(acomp_findings))
    if args.twistlock:
        log.debug("Importing twistlock findings")
        tl_findings = generate_twistlock_findings(args.twistlock)
        log.debug("Twistlock finding count: %s", len(tl_findings))
    all_findings = tl_findings + asec_findings + acomp_findings + os_findings
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
        "findings": all_findings,
        "keywords": keyword_list,
        "tags": tag_list,
        "labels": label_dict,
        "renovateEnabled": renovate_enabled,
    }
    log.debug(large_data)
    return large_data


def get_parent_vat_response(
    output_dir: str, hardening_manifest: HardeningManifest
) -> None:
    """Pulls the parent VAT response for a particular image from a registry.

    This function takes an output directory and a hardening manifest. It then sets up
    the necessary docker configurations and uses Cosign to download the base image,
    then it moves the VAT predicate file to the appropriate path.

    Environment Variables:
    - BASE_REGISTRY: The registry from where to pull the base image.
    - DOCKER_AUTH_FILE_PULL: The path to the docker authentication file.

    Arguments:
    - output_dir: The directory where the output will be stored.
    - hardening_manifest: The hardening manifest for the base image.
    """
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


def main() -> None:
    """Main function to run the application.

    This function collects data for an API call and sends a POST request to the API
    with the gathered data. If the base image name exists in the hardening manifest,
    it also fetches the parent VAT response.

    The function will exit the application and log an error if it encounters an
    exception during the API call.

    Environment Variables:
    - LOGLEVEL: (Optional) The log level. Defaults to 'INFO'.
    - ARTIFACT_DIR: The directory where artifacts will be stored.
    - VAT_TOKEN: The token used for authorization with the VAT API.
    """
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)

    if hardening_manifest.base_image_name:
        get_parent_vat_response(
            output_dir=os.environ["ARTIFACT_DIR"], hardening_manifest=hardening_manifest
        )
        parent_vat_path = Path(f"{os.environ['ARTIFACT_DIR']}/parent_vat_response.json")
        with parent_vat_path.open("r", encoding="UTF-8") as f:
            parent_vat_response_content = {"vatAttestationLineage": json.load(f)}
        log.debug(parent_vat_response_content)
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

    headers: CaseInsensitiveDict = CaseInsensitiveDict()
    headers["Content-Type"] = "application/json"
    headers["Authorization"] = f"Bearer {os.environ['VAT_TOKEN']}"
    try:
        resp = requests.post(
            args.api_url, headers=headers, json=large_data, timeout=(30, 30)
        )
        resp.raise_for_status()
        log.debug("API Response:\n%s", resp.text)
        log.debug("POST Response: %s", resp.status_code)
        with Path(f"{os.environ['ARTIFACT_DIR']}/vat_response.json").open(
            "w", encoding="utf-8"
        ) as outfile:
            json.dump(resp.json(), outfile)
    except RuntimeError:
        log.exception("RuntimeError: API Call Failed")
        sys.exit(1)
    except requests.exceptions.HTTPError:
        # only include errors provided by VAT endpoint
        if resp.text and resp.status_code != 500:
            log.error("API Response:\n%s", resp.text)
        log.exception("HTTP error")
        sys.exit(1)
    except requests.exceptions.RequestException:
        log.exception("Error submitting data to VAT scan import API")
        sys.exit(1)
    except Exception:  # pylint: disable=W0718
        log.exception("Exception: Unknown exception")
        sys.exit(1)


if __name__ == "__main__":
    args = EnvUtil()

    REMOTE_REPORT_DIRECTORY = f"{args.timestamp}_{args.commit_hash}"

    if "pipeline-test-project" in args.repo_link:
        log.info(
            "Skipping vat. Cannot push to VAT when working with pipeline test projects..."
        )
        sys.exit(0)

    main()
