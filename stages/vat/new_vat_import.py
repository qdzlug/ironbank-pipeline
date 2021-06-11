#!/usr/bin/env python3

"""
This module parses CSV files into json.
"""
from pathlib import Path
import argparse
import logging
import logging.handlers
import os
import re
import sys
import ast
import json
import pandas
import requests
from requests.structures import CaseInsensitiveDict

parser = argparse.ArgumentParser(description="API Agent")

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
    "-sl",
    "--sec_link",
    help="Link to openscap security reports directory",
    required=True,
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
    "-a",
    "--api_url",
    help="Url for API POST",
    default="http://localhost:4000/internal/import/scan",
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


def remove_lame_header_row(mod_me):
    """
    @params string file name to be modified
    Remove the header row if found in csv that contains a bunch of quotes
    """
    with open(mod_me, "r+") as input_file:
        temp = input_file.readline()
        if ",,,," in temp:
            logs.debug("*****************REMOVING HEADER LINE***********************")
            data = input_file.read()  # read the rest
            input_file.seek(0)  # set the cursor to the top of the file
            input_file.write(data)  # write the data back
            input_file.truncate()  # set the file size to the current size


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
    mylist = []
    for j in enumerate(d_f_clean.values):
        mylist.append(j[1])
    retset = []
    for l_item in mylist:
        temp = {
            "finding": l_item[0],
            "severity": l_item[1].lower(),
            "description": l_item[2],
            "link": l_item[3],
            "score": l_item[4],
            "package": l_item[5],
            "packagePath": l_item[6],
            "scanSource": "twistlock_cve",
        }
        retset.append(temp)
    logs.debug(f"twistlock dataframe: \n {d_f_clean}")
    return retset


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
    d_f["description"] = d_f["description"] + "\n" + "Link:\n" + d_f["link"]

    # Temporarily Removing imported link and replacing with None
    d_f.drop(columns=["link"], inplace=True)
    d_f = d_f.assign(link=None)

    # REMOVE THIS ONCE PACKAGE PATH FIELD IS ADDED TO DB
    # d_f.drop(columns=["package_path"], inplace=True)

    # needed to add empty row to match twistlock
    d_f = d_f.assign(score="")

    d_f_clean = d_f.where(pandas.notnull(d_f), None)
    mylist = []
    for j in enumerate(d_f_clean.values):
        mylist.append(j[1])
    retset = []
    for l_item in mylist:
        temp = {
            "finding": l_item[0],
            "severity": l_item[1].lower(),
            "description": l_item[4],
            "link": l_item[5],
            "score": l_item[6],
            "package": l_item[2],
            "packagePath": l_item[3],
            "scanSource": "anchore_cve",
        }
        retset.append(temp)
    logs.debug(f"anchore security dataframe: \n {d_f_clean}")
    return retset


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

    mylist = []
    for j in enumerate(d_f_clean.values):
        mylist.append(j[1])
    retset = []
    for l_item in mylist:
        temp = {
            "finding": l_item[0],
            "severity": l_item[2].lower(),
            "description": l_item[1],
            "link": l_item[3],
            "score": l_item[4],
            "package": l_item[5],
            "packagePath": l_item[6],
            "scanSource": "anchore_comp",
        }
        retset.append(temp)
    return retset


def get_packages(package_string):
    """
    Return a list of packages from the input string.
    """

    logs.debug("In packages: %s", package_string)

    # This will basically remove Updated from an "Updated kernel" package.
    # Capture the package
    # Remove any security, enhancement, bug fix or any combination of those.
    # Match and throw away anything after this up to the severity ().
    initial_re = ".*: (?:Updated )?(.*?)(?:security|enhancement|bug fix).*\\("
    logs.debug("packages - perform pattern match %s", initial_re)
    match = re.match(initial_re, package_string)

    pkgs = match.group(1) if match else None
    logs.debug("After pattern match, pkgs: %s", pkgs)

    # Catch all if no packages are found
    if pkgs is None or pkgs.strip(" ") == "":
        pkgs = "Unknown"

    # This will break up multiple packages as a list.
    #   Note: that single packages will be returned as a list.
    pkglist = re.split(", and |, | and ", pkgs.strip(" ").replace(":", "-"))

    logs.debug("packages list: %s", pkglist)

    return pkglist


def parse_oscap_security(ov_path):
    """
    @return dataframe with standarized columns for OSCAP security scan
    """

    report_link = os.path.join(args.sec_link, "report-cve.html")

    logs.debug("parse oscap security")
    d_f = pandas.read_csv(ov_path)

    # This keeps the rows where the result is "true" - pandas loads it as a boolean
    oscap_security = d_f[d_f["result"]]

    # grab the relevant columns we are homogenizing
    d_f = oscap_security[["ref", "title", "severity"]]

    # severity column generated and validated during OVAL XML parsing

    # Assign the column to a dataframe.
    # Apply the function to the dataframe (single column).
    # Assign the new dataframe as the package column in the dataframe.`
    logs.debug("oscap security - determine package info")
    df_pkg = d_f["title"]
    df_pkg = df_pkg.apply(get_packages)
    d_f["package"] = df_pkg

    d_f.drop(columns=["title"], inplace=True)

    d_f.rename(columns={"ref": "finding"}, inplace=True)

    d_f = d_f.assign(link=report_link)
    d_f = d_f.assign(description="")

    # needed to add empty row to match twistlock
    d_f = d_f.assign(score="")

    d_f = d_f.assign(package_path=None)

    # The following will split into rows by each package in the list.
    # Each row is duplicated with a package in each list.
    df_split = d_f.explode("package").reset_index(drop=True)

    d_f_clean = df_split.where(pandas.notnull(df_split), None)

    mylist = []
    for j in enumerate(d_f_clean.values):
        mylist.append(j[1])
    retset = []
    for l_item in mylist:
        temp = {
            "finding": l_item[0],
            "severity": l_item[1].lower(),
            "description": l_item[4],
            "link": l_item[3],
            "score": l_item[5],
            "package": l_item[2],
            "packagePath": l_item[6],
            "scanSource": "oscap_cve",
        }
        retset.append(temp)
    logs.debug(f"oscap security dataframe: \n {d_f_clean}")
    return retset


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
    d_f = d_f.assign(link=report_link)

    # needed to add empty row to match twistlock
    d_f = d_f.assign(score="")

    # This field is not used by the compliance scans
    d_f = d_f.assign(package=None)

    d_f = d_f.assign(package_path=None)

    d_f_clean = d_f.where(pandas.notnull(d_f), None)
    mylist = []
    for j in enumerate(d_f_clean.values):
        mylist.append(j[1])
    retset = []
    for l_item in mylist:
        temp = {
            "finding": l_item[1],
            "severity": l_item[0].lower(),
            "description": l_item[2],
            "link": l_item[3],
            "score": l_item[4],
            "package": l_item[5],
            "packagePath": l_item[6],
            "scanSource": "oscap_comp",
        }
        retset.append(temp)
    logs.debug(f"oscap compliance dataframe: \n {d_f_clean}")
    return retset


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
    oscap_cve = []
    oscap_comp = []
    data_json = []

    distroless = os.environ.get("DISTROLESS", None)
    if csv_dir.is_dir():
        tl_path = csv_dir.joinpath("tl.csv")
        if tl_path.exists():
            logs.debug("Parsing Twistlock CSV\n")
            remove_lame_header_row(tl_path)
            try:
                twistlock_cve = parse_twistlock_security(tl_path)
            except Exception as error:
                logs.error(f"Failed to parse twistlock \n{error}")
        as_path = csv_dir.joinpath("anchore_security.csv")
        if as_path.exists():
            logs.debug("Parsing Anchore Security CSV\n")
            remove_lame_header_row(as_path)
            try:
                anchore_cve = parse_anchore_security(as_path)
            except Exception as error:
                logs.error(f"Failed to parse anchore cve \n{error}")
        ac_path = csv_dir.joinpath("anchore_gates.csv")
        if ac_path.exists():
            logs.debug("Parsing Anchore Compliance CSV\n")
            remove_lame_header_row(ac_path)
            try:
                anchore_comp = parse_anchore_compliance(ac_path)
            except Exception as error:
                logs.error(f"Failed to parse anchore compliance \n{error}")
        ov_path = csv_dir.joinpath("oval.csv")
        if ov_path.exists() and not distroless:
            logs.debug("Parsing OSCAP Security CSV\n")
            remove_lame_header_row(ov_path)
            try:
                oscap_cve = parse_oscap_security(ov_path)
            except Exception as error:
                logs.error(f"Failed to parse oscap cve \n{error}")
        os_path = csv_dir.joinpath("oscap.csv")
        if os_path.exists() and not distroless:
            logs.debug("Parsing OSCAP Compliance CSV\n")
            remove_lame_header_row(os_path)
            try:
                oscap_comp = parse_oscap_compliance(os_path)
            except Exception as error:
                logs.error(f"Failed to parse oscap compliance \n{error}")

        data_json = twistlock_cve + anchore_cve + anchore_comp + oscap_cve + oscap_comp

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
    large_data = parse_csvs()

    if args.dump_json:
        with open(args.out_file, "w") as outfile:
            json.dump(large_data, outfile)

    headers = CaseInsensitiveDict()
    headers["Content-Type"] = "application/json"
    try:
        # TODO: Confirm the port prod hosts the API endpoint on.
        resp = None
        resp = requests.post(args.api_url, headers=headers, json=large_data)
        resp.raise_for_status()
    except Exception as error:
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
