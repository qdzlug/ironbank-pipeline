#!/usr/bin/env python3

import os
import re
import csv
import json
import pathlib
import logging
import argparse
import pandas as pd
from bs4 import BeautifulSoup

from scanners import anchore
from scanners.helper import _write_csv_from_dict_list


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
    args = parser.parse_args()

    pathlib.Path(args.output_dir).mkdir(parents=True, exist_ok=True)

    oscap_fail_count = 0
    oval_fail_count = 0
    twist_fail_count = 0
    anchore_num_cves = 0
    anchore_compliance = {"stop_count": 0, "image_id": None}

    if args.oscap:
        oscap_fail_count = generate_oscap_report(
            csv_dir=args.output_dir, oscap=args.oscap
        )
    else:
        generate_blank_oscap_report(csv_dir=args.output_dir)
    if args.oval:
        oval_fail_count = generate_oval_report(csv_dir=args.output_dir, oval=args.oval)
    else:
        generate_blank_oval_report(csv_dir=args.output_dir)
    if args.twistlock:
        twist_fail_count = generate_twistlock_report(
            csv_dir=args.output_dir, twistlock_cve_json=args.twistlock
        )
    if args.anchore_sec:
        anchore_num_cves = anchore.vulnerability_report(
            csv_dir=args.output_dir, anchore_security_json=args.anchore_sec
        )
    if args.anchore_gates:
        anchore_compliance = anchore.compliance_report(
            csv_dir=args.output_dir, anchore_gates_json=args.anchore_gates
        )

    generate_summary_report(
        csv_dir=args.output_dir,
        osc=oscap_fail_count,
        ovf=oval_fail_count,
        tlf=twist_fail_count,
        anchore_num_cves=anchore_num_cves,
        anchore_compliance=anchore_compliance,
    )
    convert_to_excel(csv_dir=args.output_dir)


# convert to Excel file
def convert_to_excel(csv_dir):
    read_sum = pd.read_csv(csv_dir + "summary.csv")
    read_oscap = pd.read_csv(csv_dir + "oscap.csv")
    read_oval = pd.read_csv(csv_dir + "oval.csv")
    read_tl = pd.read_csv(csv_dir + "tl.csv")
    read_security = pd.read_csv(csv_dir + "anchore_security.csv")
    read_gates = pd.read_csv(csv_dir + "anchore_gates.csv")
    with pd.ExcelWriter(
        csv_dir + "all_scans.xlsx"
    ) as writer:  # pylint: disable=abstract-class-instantiated
        read_sum.to_excel(writer, sheet_name="Summary", header=True, index=False)
        read_oscap.to_excel(
            writer, sheet_name="OpenSCAP - DISA Compliance", header=True, index=False
        )
        read_oval.to_excel(
            writer, sheet_name="OpenSCAP - OVAL Results", header=True, index=False
        )
        read_tl.to_excel(
            writer,
            sheet_name="Twistlock Vulnerability Results",
            header=True,
            index=False,
        )
        read_security.to_excel(
            writer, sheet_name="Anchore CVE Results", header=True, index=False
        )
        read_gates.to_excel(
            writer, sheet_name="Anchore Compliance Results", header=True, index=False
        )
    writer.save()


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
    sha_str = (
        "Scans performed on container layer sha256:"
        + anchore_compliance["image_id"]
        + ",,,"
    )
    csv_writer.writerow([sha_str])
    sum_data.close()


def generate_oscap_report(csv_dir, oscap):
    oscap_cves = get_oscap_full(oscap)
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
            print("problem writing line:", line.values())
            raise e
    oscap_data.close()
    return fail_count, nc_count, scanned


def get_oscap_full(oscap_file):
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
            }
            cces.append(ret)
        return cces


# OVAL CSV
def generate_oval_report(csv_dir, oval):
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


def get_oval_full(oval_file):
    oscap = open(oval_file, "r", encoding="utf-8")
    soup = BeautifulSoup(oscap, "html.parser")
    results_bad = soup.find_all("tr", class_=["resultbadA", "resultbadB"])
    results_good = soup.find_all("tr", class_=["resultgoodA", "resultgoodB"])

    cves = []
    for x in results_bad + results_good:
        id = x.find("td")
        result = id.find_next_sibling("td")
        cls = result.find_next_sibling("td")
        y = x.find_all(target="_blank")
        references = set()
        for t in y:
            references.add(t.text)
        title = cls.find_next_sibling("td").find_next_sibling("td")

        for ref in references:
            ret = {
                "id": id.text,
                "result": result.text,
                "cls": cls.text,
                "ref": ref,
                "title": title.text,
            }
            cves.append(ret)
    return cves


def generate_twistlock_report(csv_dir, twistlock_cve_json):
    with open(twistlock_cve_json, mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
        if json_data[0]["vulnerabilities"] is None:
            cves = []
        else:
            cves = [
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
                }
                for d in json_data[0]["vulnerabilities"]
            ]
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
    ]

    _write_csv_from_dict_list(
        csv_dir=csv_dir, dict_list=cves, fieldnames=fieldnames, filename="tl.csv"
    )

    return len(cves)


if __name__ == "__main__":
    main()  # with if
