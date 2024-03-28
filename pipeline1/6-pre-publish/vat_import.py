#!/usr/bin/env python3

import json
import os
import shutil
import sys
from itertools import groupby
from pathlib import Path
from typing import Any, Generator, Tuple

import requests
from args import EnvUtil
from common.utils import logger
from pipeline.container_tools.cosign import Cosign
from pipeline.harbor import get_json_for_image_or_manifest_list
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
from requests.structures import CaseInsensitiveDict

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


def create_api_call(platform) -> dict:
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
    # append platform
    tag_list = [f"{tag}-{platform}" for tag in tag_list]
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

    with open(
        f'{os.environ["ARTIFACT_STORAGE"]}/scan-logic/{platform}/scan_logic.json',
        encoding="utf-8",
    ) as f:
        scan_logic = json.load(f)

    with open(
        f'{os.environ["ARTIFACT_STORAGE"]}/build/{platform}/build.json',
        encoding="utf-8",
    ) as f:
        build_json = json.load(f)

    # OSCAP_DATASTREAM is set by image_inspect.py and the value depends on the base image
    # if OSCAP_DATASTREAM is set, oscap_scan.sh produced a report artifact and vat can import
    if args.oscap and os.environ.get("OSCAP_DATASTREAM"):
        log.info("Importing oscap findings")
        os_findings = generate_oscap_findings(
            args.oscap, vat_finding_fields=vat_finding_fields
        )
        log.info("oscap finding count: %s", len(os_findings))
    if args.anchore_sec:
        log.info("Importing anchore security findings")
        asec_findings = generate_anchore_cve_findings(
            args.anchore_sec, vat_finding_fields=vat_finding_fields
        )
        log.info("Anchore security finding count: %s", len(asec_findings))
    if args.anchore_gates:
        log.info("Importing importing anchore compliance findings")
        acomp_findings = generate_anchore_comp_findings(args.anchore_gates)
        log.info("Anchore compliance finding count: %s", len(acomp_findings))
    if args.twistlock:
        log.info("Importing twistlock findings")
        tl_findings = generate_twistlock_findings(args.twistlock)
        log.info("Twistlock finding count: %s", len(tl_findings))
    all_findings = tl_findings + asec_findings + acomp_findings + os_findings
    # Allows the multiarch pipeline1 to run legacy projects in prod until other teams are ready.
    # args.version ==> This value comes from args.version, which gets it from the Environment var IMAGE_VERSION which is written by the hardening_manifest_validation.py script run.
    if platform == "amd64":
        image_tag = args.version
    else:
        image_tag = args.version + "-" + platform
    large_data = {
        "imageName": args.container,
        "imageTag": image_tag,
        "parentImageName": args.parent,
        "parentImageTag": args.parent_version,
        "jobId": args.job_id,
        "digest": str(scan_logic["DIGEST_TO_SCAN"].replace("sha256:", "")),
        "timestamp": args.timestamp,
        "scanDate": str(build_json["BUILD_DATE"]),
        "buildDate": str(scan_logic["BUILD_DATE_TO_SCAN"]),
        "repo": {
            "url": os.environ["CI_PROJECT_URL"],
            "commit": str(scan_logic["COMMIT_SHA_TO_SCAN"]),
        },
        "findings": all_findings,
        "keywords": keyword_list,
        "tags": tag_list,
        "labels": label_dict,
        "renovateEnabled": renovate_enabled,
        "registryLocation": os.environ.get("REGISTRY_PUBLISH_URL", ""),
    }
    log.info(large_data)
    return large_data


def get_parent_vat_response(
    output_dir: str, hardening_manifest: HardeningManifest, digest: str = None
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
    # If digest != None that means the base image was a manifest list.
    if digest is not None:
        base_image = Image(
            registry=os.environ["BASE_REGISTRY"],
            name=hardening_manifest.base_image_name,
            digest=digest,
        )
    else:
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
        log_cmd=True,
    )
    predicates = Predicates()
    predicate_path = Path(
        output_dir, predicates.get_predicate_files()[vat_response_predicate]
    )
    parent_vat_path = Path(output_dir, "parent_vat_response.json")
    shutil.move(predicate_path, parent_vat_path)


def main(platform: str) -> None:
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
        # Check if the base image is a manifest list.
        try:
            json_data = get_json_for_image_or_manifest_list(hardening_manifest)
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            sys.exit(1)
        # 2. If manifest list use image sha's
        if (
            json_data["manifest_media_type"]
            == "application/vnd.oci.image.index.v1+json"
        ):
            for image in json_data["references"]:
                if image["platform"]["architecture"] == platform:
                    digest = image["child_digest"]
                    get_parent_vat_response(
                        output_dir=f'{os.environ["ARTIFACT_DIR"]}/{platform}',
                        hardening_manifest=hardening_manifest,
                        digest=digest,
                    )
                    parent_vat_path = Path(
                        f"{os.environ['ARTIFACT_DIR']}/{image['platform']['architecture']}/parent_vat_response.json"
                    )
                    with parent_vat_path.open("r", encoding="utf-8") as f:
                        parent_vat_response_content = {
                            "parentVatResponses": json.load(f)
                        }
                    log.info(
                        f"parent_vat_response_content for {platform} in 2 --> {parent_vat_response_content}"
                    )
        # 3. If not manifest list use image tag.
        else:
            get_parent_vat_response(
                output_dir=f'{os.environ["ARTIFACT_DIR"]}/{platform}',
                hardening_manifest=hardening_manifest,
            )
            parent_vat_path = Path(
                f"{os.environ['ARTIFACT_DIR']}/{json_data['extra_attrs']['architecture']}/parent_vat_response.json"
            )
            with parent_vat_path.open("r", encoding="utf-8") as f:
                parent_vat_response_content = {"parentVatResponses": json.load(f)}
            log.info(
                f"parent_vat_response_content for {platform} in 3 --> {parent_vat_response_content}"
            )
    else:
        parent_vat_response_content = {"parentVatResponses": None}
        log.info(
            f"parent_vat_response_content in else with platform {platform} --> {parent_vat_response_content}"
        )

    vat_request_json = Path(f"{os.environ['ARTIFACT_DIR']}/{platform}/vat_request.json")
    if not args.use_json:
        large_data = create_api_call(platform)
        large_data.update(parent_vat_response_content)
        log.info(
            f"large_data after .update(parent_vat_response_content --> {large_data}"
        )
        with vat_request_json.open("w", encoding="utf-8") as outfile:
            json.dump(large_data, outfile)
    else:
        with vat_request_json.open(encoding="utf-8") as infile:
            large_data = json.load(infile)

    headers: CaseInsensitiveDict = CaseInsensitiveDict()
    headers["Content-Type"] = "application/json"
    headers["Authorization"] = f"Bearer {os.environ['VAT_TOKEN']}"
    log.info("Connecting to VAT")
    try:
        resp = requests.post(
            args.api_url, headers=headers, json=large_data, timeout=(90, 90)
        )
        resp.raise_for_status()
        log.info("API Response:\n%s", resp.text)
        log.info("POST Response: %s", resp.status_code)
        with Path(f"{os.environ['ARTIFACT_DIR']}/{platform}/vat_response.json").open(
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
    potential_platforms = [
        "amd64",
        "arm64",
    ]

    platforms = [
        platform
        for platform in potential_platforms
        if os.path.isfile(
            f'{os.environ["ARTIFACT_STORAGE"]}/scan-logic/{platform}/scan_logic.json'
        )
    ]
    for p in platforms:
        args = EnvUtil(p)

        Path(f"{os.environ['ARTIFACT_DIR']}/{p}").mkdir(parents=True, exist_ok=True)
        REMOTE_REPORT_DIRECTORY = f"{args.timestamp}_{args.commit_hash}"

        if "pipeline-test-project" in args.repo_link:
            log.info(
                "Skipping vat. Cannot push to VAT when working with pipeline test projects..."
            )
            sys.exit(0)

        main(p)
