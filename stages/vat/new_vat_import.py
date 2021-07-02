#!/usr/bin/env python3

"""
This module parses CSV files into json.
"""
from pathlib import Path
import argparse
import logging
import logging.handlers
import os
import sys
import ast
import json
import pandas
import requests
from requests.structures import CaseInsensitiveDict

parser = argparse.ArgumentParser(description="API Agent")

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

# This shuts off pandas informational messages for row manipulation
pandas.options.mode.chained_assignment = None


def construct_job_parts(finding_tuples, source):
    """
    Construct a list of JSON objects for API Call
    """
    retset = []
    for l_item in finding_tuples:
        temp = {
            "finding": l_item.finding,
            "severity": l_item.severity.lower(),
            "description": l_item.description,
            "link": l_item.link,
            "score": l_item.score,
            "package": l_item.package,
            "packagePath": l_item.package_path,
            "scanSource": source,
        }
        retset.append(temp)
    logs.debug(f"dataframe: \n {finding_tuples}")
    return retset


def parse_twistlock_security(tl_path):
    """
    Creates dataframe  with standarized columns for a twistlock scan
    Return a dataframe
    """

    twistlock = pandas.read_csv(tl_path)

    # grab the relevant columns we are homogenizing
    d_f = twistlock[
        ["id", "severity", "desc", "link", "cvss", "packageName", "packageVersion"]
    ]
    d_f.rename(
        columns={"id": "finding", "desc": "description", "cvss": "score"},
        inplace=True,
    )

    d_f["package"] = d_f["packageName"] + "-" + d_f["packageVersion"]
    d_f.drop(columns=["packageName", "packageVersion"], inplace=True)

    d_f = d_f.assign(package_path=None)

    d_f_clean = d_f.where(pandas.notnull(d_f), None)

    return construct_job_parts(d_f_clean.itertuples(), "twistlock_cve")


def parse_anchore_json(links):
    """
    @params string of either a url or a list of dicts
    Returns a URL If list, returns string of sources and urls
    """
    try:
        source_list = ast.literal_eval(links)
        link_string = "".join(
            (item["source"] + ": " + item["url"] + "\n") for item in source_list
        )
        return link_string
    except SyntaxError as error:
        logs.debug(error)
        return links


def parse_anchore_security(as_path):
    """
    @return dataframe with standarized columns for anchore security scan
    """
    anchore_security = pandas.read_csv(as_path)
    # grab the relevant columns we are homogenizing

    d_f = anchore_security[
        ["cve", "severity", "package", "url", "package_path", "description"]
    ]

    # replace pkgdb to None
    d_f.replace({"package_path": {"pkgdb": None}}, inplace=True)

    d_f.rename(columns={"cve": "finding", "url": "link"}, inplace=True)
    d_f["link"] = d_f["link"].apply(parse_anchore_json)

    # needed to add empty row to match twistlock
    d_f = d_f.assign(score="")

    d_f_clean = d_f.where(pandas.notnull(d_f), None)

    return construct_job_parts(d_f_clean.itertuples(), "anchore_cve")


def parse_anchore_compliance(ac_path):
    """
    @return dataframe with standarized columns for anchore compliance scan
    """

    d_f = pandas.read_csv(ac_path)

    # This removes the rows where the gate does <> 'vulnerabilities'
    anchore_compliance = d_f[(d_f["gate"] != "vulnerabilities")]

    # grab the relevant columns we are homogenizing
    d_f = anchore_compliance[
        ["trigger_id", "check_output", "gate_action", "gate", "trigger", "policy_id"]
    ]

    # Prepend the action with "ga_" to distinguish from other severity types
    d_f["gate_action"] = "ga_" + d_f["gate_action"].astype(str)

    d_f.rename(
        columns={
            "trigger_id": "finding",
            "gate_action": "severity",
            "check_output": "description",
        },
        inplace=True,
    )

    d_f["description"] = d_f["description"] + "\n Gate: " + d_f["gate"]
    d_f["description"] = d_f["description"] + "\n Trigger: " + d_f["trigger"]
    d_f["description"] = d_f["description"] + "\n Policy ID: " + d_f["policy_id"]
    d_f.drop(columns=["gate", "trigger", "policy_id"], inplace=True)

    # No link available for this scan
    d_f = d_f.assign(link=None)

    # needed to add empty row to match twistlock
    d_f = d_f.assign(score="")

    # This field is not used by the compliance scans
    d_f = d_f.assign(package=None)

    d_f = d_f.assign(package_path=None)

    d_f_clean = d_f.where(pandas.notnull(d_f), None)
    logs.debug(f"anchore compliance dataframe: \n {d_f_clean}")

    return construct_job_parts(d_f_clean.itertuples(), "anchore_comp")


def parse_oscap_compliance(os_path):
    """
    @return dataframe with standarized columns for OpenSCAP compliance scan
    """

    report_link = os.path.join(args.comp_link, "report.html")
    d_f = pandas.read_csv(os_path)

    # This keeps the rows where the result is fail or notchecked or error
    oscap_compliance = d_f[
        (d_f["result"] == "fail")
        | (d_f["result"] == "notchecked")
        | (d_f["result"] == "error")
    ]

    # grab the relevant columns we are homogenizing
    d_f = oscap_compliance[["severity", "identifiers", "title"]]

    # The XCCDF parsing will return exactly one identifier in d_f["identifiers"]
    # Values will be of the format CCE-12345-1 (UBI) or CCI-001234 (Ubuntu)

    d_f.rename(columns={"identifiers": "finding", "title": "description"}, inplace=True)
    d_f = d_f.assign(link=None)

    # needed to add empty row to match twistlock
    d_f = d_f.assign(score="")

    # This field is not used by the compliance scans
    d_f = d_f.assign(package=None)

    d_f = d_f.assign(package_path=None)

    d_f_clean = d_f.where(pandas.notnull(d_f), None)

    return construct_job_parts(d_f_clean.itertuples(), "oscap_comp")


def parse_csvs():
    """
    Parse out all csvs files that match token and return dict with all data
    All parsed out csv data will be placed into a uniform dictionary with matching
    column heading for db
    @return dictionary
    """
    csv_dir = Path(args.csv_dir)
    twistlock_cve = []
    anchore_cve = []
    anchore_comp = []
    oscap_comp = []
    data_json = []

    distroless = os.environ.get("DISTROLESS", None)
    if csv_dir.is_dir():
        tl_path = csv_dir.joinpath("tl.csv")
        if tl_path.exists():
            logs.debug("Parsing Twistlock CSV\n")
            try:
                twistlock_cve = parse_twistlock_security(tl_path)
            except ValueError as error:
                logs.error(f"Failed to parse twistlock \n{error}")
        as_path = csv_dir.joinpath("anchore_security.csv")
        if as_path.exists():
            logs.debug("Parsing Anchore Security CSV\n")
            try:
                anchore_cve = parse_anchore_security(as_path)
            except ValueError as error:
                logs.error(f"Failed to parse anchore cve \n{error}")
        ac_path = csv_dir.joinpath("anchore_gates.csv")
        if ac_path.exists():
            logs.debug("Parsing Anchore Compliance CSV\n")
            try:
                anchore_comp = parse_anchore_compliance(ac_path)
            except ValueError as error:
                logs.error(f"Failed to parse anchore compliance \n{error}")
        os_path = csv_dir.joinpath("oscap.csv")
        if os_path.exists() and not distroless:
            logs.debug("Parsing OSCAP Compliance CSV\n")
            try:
                oscap_comp = parse_oscap_compliance(os_path)
            except ValueError as error:
                logs.error(f"Failed to parse oscap compliance \n{error}")

        data_json = twistlock_cve + anchore_cve + anchore_comp + oscap_comp

        request_dict = {
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
            "findings": data_json,
        }
        logs.debug("Total Findings Parsed: %d\n", len(data_json))
        return request_dict

    logs.error("\nArgument for csv directory is not a valid directory")
    return False


def main():
    """
    Construct API calls from CSVs
    """
    large_data = parse_csvs()

    if args.dump_json:
        with open(args.out_file, "w") as outfile:
            json.dump(large_data, outfile)

    headers = CaseInsensitiveDict()
    headers["Content-Type"] = "application/json"
    try:
        resp = None
        resp = requests.post(args.api_url, headers=headers, json=large_data)
        resp.raise_for_status()
    except RuntimeError as error:
        logs.error(f"API Call Failed: {error}")
        sys.exit(1)
    finally:
        if resp:
            logs.debug("API Response:\n %s", resp.text)
            logs.debug("POST Response: %s", resp.status_code)
        logs.info("Exiting new_vat_import_logging")


if __name__ == "__main__":
    args = parser.parse_args()
    logs = logging.getLogger("findings")
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
    logs.info("\n*****************************\n\n")
    logs.info("SQL Agent\n\n*****************************\n\n")
    logs.info("Args\n----------------------------")
    logs.info(args)
    logs.info("\n\n")
    main()
