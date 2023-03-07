#!/usr/bin/env python3

import csv
import sys
import json
import os
from pathlib import Path

from ironbank.pipeline.scan_report_parsers.anchore import AnchoreSecurityParser
from ironbank.pipeline.scan_report_parsers.oscap import OscapReportParser

from ironbank.pipeline.scan_report_parsers.report_parser import ReportParser
from ironbank.pipeline.utils import logger

from ironbank.pipeline.vat_container_status import sort_justifications

log = logger.setup("csv_gen")


def main() -> None:
    # Get logging level, set manually when running pipeline

    anchore_cve_path = Path(f"{os.environ['ANCHORE_SCANS']}/anchore_security.json")
    anchore_comp_path = Path(f"{os.environ['ANCHORE_SCANS']}/anchore_gates.json")
    twistlock_cve_path = Path(f"{os.environ['TWISTLOCK_SCANS']}/twistlock_cve.json")
    oscap_comp_path = Path(f"{os.environ['OSCAP_SCANS']}/compliance_output_report.xml")
    csv_output_dir = Path(os.environ["CSV_REPORT"])

    # Create the csv directory if not present
    Path(csv_output_dir).mkdir(parents=True, exist_ok=True)

    artifacts_path = os.environ["ARTIFACT_STORAGE"]
    # get cves and justifications from VAT
    vat_findings_file = Path(artifacts_path, "vat", "vat_response.json")
    # load vat_findings.json file
    try:
        with vat_findings_file.open(mode="r", encoding="utf-8") as f:
            vat_findings = json.load(f)
    except Exception:
        log.exception("Error reading findings file.")
        sys.exit(1)

    log.info("Gathering list of all justifications...")

    j_anchore_cve, j_anchore_comp, j_openscap, j_twistlock = sort_justifications(
        vat_findings
    )

    oscap_comp_fail_count = 0
    oscap_comp_not_checked_count = 0
    twistlock_cve_fail_count = 0
    anchore_cve_fail_count = 0
    anchore_comp_fail_count = 0
    image_id = ""
    if "DISTROLESS" not in os.environ:
        (
            oscap_comp_fail_count,
            oscap_comp_not_checked_count,
        ) = generate_oscap_compliance_report(
            report_path=oscap_comp_path,
            csv_output_dir=csv_output_dir,
            justifications=j_openscap,
        )
    else:
        generate_blank_oscap_report(csv_output_dir=csv_output_dir)

    twistlock_cve_fail_count = generate_twistlock_cve_report(
        report_path=twistlock_cve_path,
        csv_output_dir=csv_output_dir,
        justifications=j_twistlock,
    )
    anchore_cve_fail_count = generate_anchore_cve_report(
        report_path=anchore_cve_path,
        csv_output_dir=csv_output_dir,
        justifications=j_anchore_cve,
    )
    anchore_comp_fail_count, image_id = generate_anchore_compliance_report(
        report_path=anchore_comp_path,
        csv_output_dir=csv_output_dir,
        justifications=j_anchore_comp,
    )

    generate_summary_report(
        oscap_comp_fail_count=oscap_comp_fail_count,
        oscap_comp_not_checked_count=oscap_comp_not_checked_count,
        twistlock_cve_fail_count=twistlock_cve_fail_count,
        anchore_cve_fail_count=anchore_cve_fail_count,
        anchore_comp_fail_count=anchore_comp_fail_count,
        image_id=image_id,
        csv_output_dir=csv_output_dir,
    )


def generate_blank_oscap_report(csv_output_dir: Path) -> None:
    """
    Creates an empty oscap report, used when the OpenSCAP scan was skipped.
    """
    with Path(
        csv_output_dir,
        "oscap.csv",
    ).open(mode="w", encoding="utf-8") as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(
            [
                "OpenSCAP Scan Skipped Due to Base Image Used",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
            ]
        )


def generate_summary_report(
    oscap_comp_fail_count: int,
    oscap_comp_not_checked_count: int,
    twistlock_cve_fail_count: int,
    anchore_cve_fail_count: int,
    anchore_comp_fail_count: int,
    image_id: str,
    csv_output_dir: Path,
) -> None:
    """
    Creates a summary CSV with the finding totals from each scan
    """
    with Path(csv_output_dir, "summary.csv").open(mode="w", encoding="utf-8") as f:
        csv_writer = csv.writer(f)

        header = ["Scan", "Automated Findings", "Manual Checks", "Total"]

        oscap_comp_row = ["OpenSCAP - DISA Compliance", 0, 0, 0]
        # osc arg is a tuple, meaning the generate_oscap_report function was run
        if oscap_comp_fail_count or oscap_comp_not_checked_count:
            oscap_comp_row = [
                "OpenSCAP - DISA Compliance",
                oscap_comp_fail_count,
                oscap_comp_not_checked_count,
                oscap_comp_fail_count + oscap_comp_not_checked_count,
            ]

        anchore_cve_row = [
            "Anchore CVE Results",
            anchore_cve_fail_count,
            0,
            anchore_cve_fail_count,
        ]
        anchore_comp_row = [
            "Anchore Compliance Results",
            anchore_comp_fail_count,
            0,
            anchore_comp_fail_count,
        ]
        twistlock_cve_row = [
            "Twistlock Vulnerability Results",
            int(twistlock_cve_fail_count or 0),
            0,
            int(twistlock_cve_fail_count or 0),
        ]
        scan_rows = [
            oscap_comp_row,
            twistlock_cve_row,
            anchore_cve_row,
            anchore_comp_row,
        ]

        csv_writer.writerow(header)
        csv_writer.writerows(scan_rows)

        totals_row: list[str | int] = ["Totals"]
        # for each column, combine totals for each row if value in cell is int
        totals_row += [sum([row[i] for row in scan_rows if isinstance(row[i], int)]) for i in range(1, len(header))]  # type: ignore

        csv_writer.writerow(totals_row)
        csv_writer.writerow("")
        sha_str = f"Scans performed on container layer sha256: {image_id},,,"
        csv_writer.writerow([sha_str])


def generate_anchore_cve_report(
    report_path: Path, csv_output_dir: Path, justifications: dict
) -> int:
    """
    Generate the anchore vulnerability report

    """

    findings = AnchoreSecurityParser.get_findings(report_path=report_path)

    fieldnames = [
        "tag",
        "cve",
        "severity",
        "feed",
        "feed_group",
        "package",
        "package_path",
        "package_type",
        "package_version",
        "fix",
        "url",
        "description",
        "nvd_cvss_v2_vector",
        "nvd_cvss_v3_vector",
        "vendor_cvss_v2_vector",
        "vendor_cvss_v3_vector",
    ]

    finding_dict_list = [
        {
            **finding.get_dict_from_fieldnames(fieldnames=fieldnames),
            "Justification": finding.get_justification(justifications),
        }
        for finding in findings
    ]

    AnchoreSecurityParser.write_csv_from_dict_list(
        csv_dir=csv_output_dir,
        dict_list=finding_dict_list,
        fieldnames=finding_dict_list[0].keys(),
        filename="anchore_security.csv",
    )

    return len(findings)


def generate_anchore_compliance_report(
    report_path: Path, csv_output_dir: Path, justifications: dict
) -> tuple[int, str]:
    """
    Get results of Anchore gates for csv export, becomes anchore compliance spreadsheet

    """
    with Path(report_path).open(encoding="utf-8") as f:
        json_data = json.load(f)
        sha = list(json_data.keys())[0]
        anchore_data = json_data[sha]["result"]["rows"]

    gates = []
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

        cve_justification = ""
        # ad[2] is trigger_id -- e.g. CVE-2020-####
        id = (ad[2], None, None)
        if ad[4] == "package":
            cve_justification = "See Anchore CVE Results sheet"

        if id in justifications:
            cve_justification = justifications[id]
        gate["Justification"] = cve_justification

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
        "Justification",
    ]

    ReportParser.write_csv_from_dict_list(
        dict_list=gates,
        fieldnames=fieldnames,
        filename="anchore_gates.csv",
        csv_dir=csv_output_dir,
    )

    return stop_count, image_id


def generate_oscap_compliance_report(
    report_path: Path, csv_output_dir: Path, justifications: dict
) -> tuple[int, int]:
    """
    Generate csv for OSCAP findings with justifications
    Calls the get_oscap_full function to first parse the OSCAP XML report.
    """
    findings = OscapReportParser.get_findings(report_path, results_filter=None)
    fieldnames = [
        "title",
        "ruleid",
        "result",
        "severity",
        "identifiers",
        "refs",
        "desc",
        "rationale",
        "scanned_date",
    ]
    findings_dict_list = [
        {
            **finding.get_dict_from_fieldnames(fieldnames=fieldnames),
            "identifiers": finding.identifier,
            "Justification": finding.get_justification(justifications=justifications),
        }
        for finding in findings
    ]

    with Path(csv_output_dir, "oscap.csv").open(mode="w", encoding="utf-8") as f:
        csv_writer = csv.writer(f)
        count = 0
        fail_count = 0
        nc_count = 0
        for line in findings_dict_list:
            if count == 0:
                header = line.keys()
                csv_writer.writerow(header)
                count += 1
            if line["result"] == "fail":
                fail_count += 1
            elif line["result"] == "notchecked":
                nc_count += 1
            try:
                csv_writer.writerow(line.values())
            except Exception as e:
                log.error("problem writing line: %s", line.values())
                raise e
    return fail_count, nc_count


def generate_twistlock_cve_report(
    report_path: Path, csv_output_dir: Path, justifications: dict
) -> int:
    """
    Get results from Twistlock report for csv export
    """
    with Path(report_path).open(mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
        cves = []
        if "vulnerabilities" in json_data["results"][0]:
            for d in json_data["results"][0]["vulnerabilities"]:
                # get associated justification if one exists
                cve_justification = ""
                identifier = (
                    d["id"],
                    f"{d['packageName']}-{d['packageVersion']}",
                    None,
                )
                if identifier in justifications.keys():
                    cve_justification = justifications[identifier]
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
                    log.error(
                        "Missing key. Please contact the Iron Bank Pipeline and Ops (POPs) team"
                    )
                    log.error(e.args)
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

    ReportParser.write_csv_from_dict_list(
        dict_list=cves, fieldnames=fieldnames, filename="tl.csv", csv_dir=csv_output_dir
    )

    return len(cves)


if __name__ == "__main__":
    main()
