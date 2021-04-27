#!/usr/bin/env python3

import csv
import sys
import re
import json
import os
import argparse
import pathlib
import logging
from bs4 import BeautifulSoup
from scanners import anchore
from scanners.helper import write_csv_from_dict_list

sys.path.append(os.path.join(os.path.dirname(__file__), "../../modules/"))
from vat_api import VATApi  # noqa


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


# Blank OSCAP Report
def generate_blank_oscap_report(csv_dir):
    oscap_report = open(csv_dir + "oscap.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(oscap_report)
    csv_writer.writerow(
        ["OpenSCAP Scan Skipped Due to Base Image Used", "", "", "", "", "", "", "", ""]
    )
    oscap_report.close()


# SUMMARY REPORT
def generate_summary_report(csv_dir, osc, tlf, anchore_num_cves, anchore_compliance):
    sum_data = open(csv_dir + "summary.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(sum_data)

    header = ["Scan", "Automated Findings", "Manual Checks", "Total"]

    # if the osc arg type is an int, the scan was skipped so output zero values
    if type(osc) == int:
        osl = ["OpenSCAP - DISA Compliance", 0, 0, 0]
    # osc arg is a tuple, meaning the generate_oscap_report function was run
    else:
        osl = ["OpenSCAP - DISA Compliance", osc[0], osc[1], osc[0] + osc[1]]

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
    csv_writer.writerow(twl)
    csv_writer.writerow(anchore_vulns)
    csv_writer.writerow(anchore_comps)
    csv_writer.writerow(
        [
            "Totals",
            osl[1] + anchore_vulns[1] + anchore_comps[1] + twl[1],
            osl[2] + anchore_vulns[2] + anchore_comps[2] + twl[2],
            osl[3] + anchore_vulns[3] + anchore_comps[3] + twl[3],
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
            # use tuple to match other scan justification comparisons
            id = (identifiers,)
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


def split_wl_by_scan_source(wl_justifications):
    cve_openscap = {}
    cve_twistlock = {}
    cve_anchore = {}
    comp_anchore = {}

    for finding in wl_justifications:
        if "cve_id" in finding.keys():
            cve_id = (
                finding["cve_id"],
                finding["package"],
                finding["package_path"],
            )

            cve_id = tuple(v for v in cve_id if v)
            logging.debug(cve_id)
            if finding["scan_source"] == "oscap_comp":
                cve_openscap[cve_id] = finding["justification"]
            elif finding["scan_source"] == "twistlock_cve":
                cve_twistlock[cve_id] = finding["justification"]
            elif finding["scan_source"] == "anchore_cve":
                cve_anchore[cve_id] = finding["justification"]
            elif finding["scan_source"] == "anchore_comp":
                comp_anchore[cve_id] = finding["justification"]
            logging.debug(f"Scan source: {finding['scan_source']}")
            logging.debug(f"CVE ID: {cve_id}")
            logging.debug(f"Justification: {finding['justification']}")

    return (cve_openscap, cve_twistlock, cve_anchore, comp_anchore)


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

    vat_api = VATApi(
        os.environ["IMAGE_NAME"],
        os.environ["IMAGE_VERSION"],
        os.environ["ARTIFACT_STORAGE"],
        os.environ["VAT_BACKEND_SERVER_ADDRESS"],
    )
    # get cves and justifications from VAT
    vat_api.get_container_data_from_file()
    wl_justifications = vat_api.generate_whitelist_justifications()
    logging.debug("Whitelist with justifications")
    logging.debug(wl_justifications)

    # turn off black formatting for the following line
    # fmt:off
    (j_openscap,j_twistlock,j_anchore_cve,j_anchore_comp,) = split_wl_by_scan_source(wl_justifications)
    # fmt: on

    oscap_fail_count = 0
    twist_fail_count = 0
    anchore_num_cves = 0
    anchore_compliance = 0
    if args.oscap:
        oscap_fail_count = generate_oscap_report(
            args.oscap, j_openscap, csv_dir=args.output_dir
        )
    else:
        generate_blank_oscap_report(csv_dir=args.output_dir)

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
        tlf=twist_fail_count,
        anchore_num_cves=anchore_num_cves,
        anchore_compliance=anchore_compliance,
    )


if __name__ == "__main__":
    main()  # with if
