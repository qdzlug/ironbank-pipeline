#!/usr/bin/env python3
import csv
from bs4 import BeautifulSoup
import re
import json
import os
import pandas as pd
import argparse
import pathlib
import logging


def main():
    global csv_dir

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

    csv_dir = args.output_dir
    if not os.path.exists(csv_dir):
        os.mkdir(csv_dir)

    oscap_fail_count = 0
    oval_fail_count = 0
    twist_fail_count = 0
    anc_sec_count = 0
    anc_gate_count = 0
    if args.oscap:
        oscap_fail_count = generate_oscap_report(args.oscap)
    else:
        generate_blank_oscap_report()
    if args.oval:
        oval_fail_count = generate_oval_report(args.oval)
    else:
        generate_blank_oval_report()
    if args.twistlock:
        twist_fail_count = generate_twistlock_report(args.twistlock)
    if args.anchore_sec:
        anc_sec_count = generate_anchore_sec_report(args.anchore_sec)
    if args.anchore_gates:
        anc_gate_count = generate_anchore_gates_report(args.anchore_gates)

    generate_summary_report(
        oscap_fail_count,
        oval_fail_count,
        twist_fail_count,
        anc_sec_count,
        anc_gate_count,
    )
    convert_to_excel()
    # csv_dir = sys.argv[6]
    # if not os.path.exists(csv_dir):
    #     os.mkdir(csv_dir)
    # generate_all_reports(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])


# GENERATES ALL OF THE REPORTS FOR ALL OF THE THINGS INCLUDING A SUMMARY INTO /tmp/csvs/
def generate_all_reports(oscap, oval, twistlock, anchore_sec, anchore_gates):
    oscap_fail_count = generate_oscap_report(oscap)
    oval_fail_count = generate_oval_report(oval)
    twist_fail_count = generate_twistlock_report(twistlock)
    anc_sec_count = generate_anchore_sec_report(anchore_sec)
    anc_gate_count = generate_anchore_gates_report(anchore_gates)

    generate_summary_report(
        oscap_fail_count,
        oval_fail_count,
        twist_fail_count,
        anc_sec_count,
        anc_gate_count,
    )

    convert_to_excel()


# convert to Excel file
def convert_to_excel():
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
def generate_blank_oscap_report():
    oscap_report = open(csv_dir + "oscap.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(oscap_report)
    csv_writer.writerow(
        ["OpenSCAP Scan Skipped Due to Base Image Used", "", "", "", "", "", "", "", ""]
    )
    oscap_report.close()


# Blank oval Report
def generate_blank_oval_report():
    oval_report = open(csv_dir + "oval.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(oval_report)
    csv_writer.writerow(
        ["OpenSCAP Scan Skipped Due to Base Image Used", "", "", "", ""]
    )
    oval_report.close()


# SUMMARY REPORT
def generate_summary_report(osc, ovf, tlf, asf, agf):
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
    ancl = ["Anchore CVE Results", int(asf or 0), 0, int(asf or 0)]
    ancc = ["Anchore Compliance Results", int(agf[0] or 0), 0, int(agf[0] or 0)]
    twl = ["Twistlock Vulnerability Results", int(tlf or 0), 0, int(tlf or 0)]

    csv_writer.writerow(header)
    csv_writer.writerow(osl)
    csv_writer.writerow(ovf)
    csv_writer.writerow(twl)
    csv_writer.writerow(ancl)
    csv_writer.writerow(ancc)
    csv_writer.writerow(
        [
            "Totals",
            osl[1] + ovf[1] + ancl[1] + ancc[1] + twl[1],
            osl[2] + ovf[2] + ancl[2] + ancc[2] + twl[2],
            osl[3] + ovf[3] + ancl[3] + ancc[3] + twl[3],
        ]
    )

    csv_writer.writerow("")
    # date_str = 'Scans performed on: ' + str(osc[2])
    # csv_writer.writerow(['Scans performed on:', ]) # need date scanned
    sha_str = "Scans performed on container layer sha256:" + agf[1] + ",,,"
    csv_writer.writerow([sha_str])
    sum_data.close()


def generate_oscap_report(oscap):
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
def generate_oval_report(oval):
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


def generate_twistlock_report(twistlock_cve_json):
    with open(twistlock_cve_json, mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
        if json_data[0]["vulnerabilities"] is None:
            cves = []
        else:
            cves = [
                {
                    "id": d["id"],
                    "cvss": d["cvss"],
                    "desc": d["description"],
                    "link": d["link"],
                    "packageName": d["packageName,"],
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

    _write_csv_from_dict_list(dict_list=cves, fieldnames=fieldnames, filename="tl.csv")

    return len(cves)


def _write_csv_from_dict_list(dict_list, fieldnames, filename):
    """
    Create csv file based off prepared data. The data must be provided as a list
    of dictionaries and the rest will be taken care of.

    """
    filepath = pathlib.Path(csv_dir, filename)

    with filepath.open(mode="w", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        if dict_list:
            writer.writerows(dict_list)


# ANCHORE SECURITY CSV
def generate_anchore_sec_report(anchore_security_json):
    with open(anchore_security_json, mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
        cves = [
            {
                "tag": json_data["imageFullTag"],
                "cve": d["vuln"],
                "severity": d["severity"],
                "package": d["package"],
                "package_path": d["package_path"],
                "fix": d["fix"],
                "url": d["url"],
                "inherited": d.get("inherited_from_base") or "no_data",
            }
            for d in json_data["vulnerabilities"]
        ]

    fieldnames = [
        "tag",
        "cve",
        "severity",
        "package",
        "package_path",
        "fix",
        "url",
        "inherited",
    ]

    _write_csv_from_dict_list(
        dict_list=cves, fieldnames=fieldnames, filename="anchore_security.csv"
    )

    return len(cves)


# ANCHORE GATES CSV
def generate_anchore_gates_report(anchore_gates_json):
    with open(anchore_gates_json, encoding="utf-8") as f:
        json_data = json.load(f)
        sha = list(json_data.keys())[0]
        anchore_data = json_data[sha]["result"]["rows"]

    gates = list()
    stop_count = 0
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

        gates.append(gate)

        if gate["gate_action"] == "stop":
            stop_count += 1

        image_id = gate["image_id"]

    fieldnames = [
        "image_id",
        "repo_tag",
        "trigger_id",
        "gate",
        "trigger",
        "check_output",
        "gate_action",
        "policy_id",
        "matched_rule_id",
        "whitelist_id",
        "whitelist_name",
        "inherited",
    ]

    _write_csv_from_dict_list(
        dict_list=gates, fieldnames=fieldnames, filename="anchore_gates.csv"
    )
    return stop_count, image_id


if __name__ == "__main__":
    main()  # with if
