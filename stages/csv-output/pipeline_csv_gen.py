#!/usr/bin/env python3

import csv
import sys
import json
import os
import argparse
import pathlib
import logging
import xml.etree.ElementTree as etree

from scanners import anchore
from scanners.helper import write_csv_from_dict_list

from ironbank.pipeline.vat_container_status import sort_justifications


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
    parser.add_argument("--oscap", help="location of the oscap scan XML file")
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

    artifacts_path = os.environ["ARTIFACT_STORAGE"]
    # get cves and justifications from VAT
    vat_findings_file = pathlib.Path(artifacts_path, "vat", "vat_response.json")
    # load vat_findings.json file
    try:
        with vat_findings_file.open(mode="r") as f:
            vat_findings = json.load(f)
    except Exception:
        logging.exception("Error reading findings file.")
        sys.exit(1)

    logging.info("Gathering list of all justifications...")

    j_openscap, j_twistlock, j_anchore_cve, j_anchore_comp = sort_justifications(
        vat_findings
    )

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

    generate_summary_report(
        csv_dir=args.output_dir,
        osc=oscap_fail_count,
        tlf=twist_fail_count,
        anchore_num_cves=anchore_num_cves,
        anchore_compliance=anchore_compliance,
    )


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
    root = etree.parse(oscap_file)
    ns = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "xhtml": "http://www.w3.org/1999/xhtml",  # not actually needed
        "dc": "http://purl.org/dc/elements/1.1/",
    }
    patches_up_to_date_dupe = False
    cces = []
    for rule_result in root.findall("xccdf:TestResult/xccdf:rule-result", ns):
        # Current CSV values
        # title,ruleid,result,severity,identifiers,refs,desc,rationale,scanned_date,Justification
        rule_id = rule_result.attrib["idref"]
        severity = rule_result.attrib["severity"]
        date_scanned = rule_result.attrib["time"]
        result = rule_result.find("xccdf:result", ns).text
        logging.debug(f"{rule_id}")
        if result == "notselected":
            logging.debug(f"SKIPPING: 'notselected' rule {rule_id} ")
            continue

        if rule_id == "xccdf_org.ssgproject.content_rule_security_patches_up_to_date":
            if patches_up_to_date_dupe:
                logging.debug(
                    f"SKIPPING: rule {rule_id} - OVAL check repeats and this finding is checked elsewhere"
                )
                continue
            else:
                patches_up_to_date_dupe = True
        # Get the <rule> that corresponds to the <rule-result>
        # This technically allows xpath injection, but we trust XCCDF files from OpenScap enough
        rule = root.find(f".//xccdf:Rule[@id='{rule_id}']", ns)
        title = rule.find("xccdf:title", ns).text

        # UBI/ComplianceAsCode:
        identifiers = [ident.text for ident in rule.findall("xccdf:ident", ns)]
        if not identifiers:
            # Ubuntu/ComplianceAsCode
            identifiers = [rule_id]
        # We never expect to get more than one identifier
        assert len(identifiers) == 1
        logging.debug(f"{identifiers}")
        identifier = identifiers[0]
        # Revisit this if we ever switch UBI from ComplianceAsCode to DISA content

        def format_reference(ref):
            ref_title = ref.find("dc:title", ns)
            ref_identifier = ref.find("dc:identifier", ns)
            href = ref.attrib.get("href")
            if ref_title is not None:
                assert ref_identifier is not None
                return f"{ref_title.text}: {ref_identifier.text}"
            elif href:
                return f"{href} {ref.text}"

            return ref.text

        # This is now informational only, vat_import no longer uses this field
        references = "\n".join(
            format_reference(r) for r in rule.findall("xccdf:reference", ns)
        )
        assert references

        rationale_element = rule.find("xccdf:rationale", ns)
        # Ubuntu XCCDF has no <rationale>
        rationale = (
            etree.tostring(rationale_element, method="text").decode("utf-8").strip()
            if rationale_element is not None
            else ""
        )

        # Convert description to text, seems to work well:
        description = (
            etree.tostring(rule.find("xccdf:description", ns), method="text")
            .decode("utf8")
            .strip()
        )

        cve_justification = ""
        id = (identifier, None, None)
        if id in justifications:
            cve_justification = justifications[id]

        ret = {
            "title": title,
            "ruleid": rule_id,
            "result": result,
            "severity": severity,
            "identifiers": identifier,
            "refs": references,
            "desc": description,
            "rationale": rationale,
            "scanned_date": date_scanned,
            "Justification": cve_justification,
        }
        cces.append(ret)
    try:
        assert len(set(cce["identifiers"] for cce in cces)) == len(cces)
    except Exception as duplicate_idents:
        for cce in cces:
            print(cce["ruleid"], cce["identifiers"])
        raise duplicate_idents

    return cces


# Get results from Twistlock report for csv export
def generate_twistlock_report(twistlock_cve_json, justifications, csv_dir):
    with open(twistlock_cve_json, mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
        cves = []
        if "vulnerabilities" in json_data["results"][0]:
            for d in json_data["results"][0]["vulnerabilities"]:
                # get associated justification if one exists
                cve_justification = ""
                # if d["description"]:
                id = (d["id"], f"{d['packageName']}-{d['packageVersion']}", None)
                # id = d["cve"] + "-" + d["description"]
                # else:
                #     id = d["cve"]
                if id in justifications.keys():
                    cve_justification = justifications[id]
                # else cve_justification is ""
                try:
                    cves.append(
                        {
                            "id": d["id"],
                            "cvss": d.get("cvss"),
                            "desc": d.get("description"),
                            "link": d.get("link"),
                            "packageName": d["packageName"],
                            "packageVersion": d["packageVersion"],
                            "severity": d["severity"],
                            "status": d.get("status"),
                            "vecStr": d.get("vector"),
                            "Justification": cve_justification,
                        }
                    )
                except KeyError as e:
                    logging.error(
                        "Missing key. Please contact the Iron Bank Pipeline and Ops (POPs) team"
                    )
                    logging.error(e.args)
                    sys.exit(1)
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


if __name__ == "__main__":
    main()  # with if
