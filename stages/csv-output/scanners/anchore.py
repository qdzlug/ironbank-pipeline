#!/usr/bin/env python3

import json
import logging
import os
import pathlib

from scanners.helper import _write_csv_from_dict_list


def _vulnerability_record(fulltag, justifications, vuln):

    vuln_record = dict()
    vuln_record["tag"] = fulltag
    vuln_record["cve"] = vuln["vuln"]
    vuln_record["severity"] = vuln["severity"]
    vuln_record["feed"] = vuln["feed"]
    vuln_record["feed_group"] = vuln["feed_group"]
    vuln_record["package"] = vuln["package"]
    vuln_record["package_path"] = vuln["package_path"]
    vuln_record["package_type"] = vuln["package_type"]
    vuln_record["package_version"] = vuln["package_version"]
    vuln_record["fix"] = vuln["fix"]
    vuln_record["url"] = vuln["url"]
    vuln_record["inherited"] = vuln.get("inherited_from_base") or "no_data"
    vuln_record["description"] = vuln["extra"]["description"]

    key = "nvd_cvss_v2_vector"
    try:
        vuln_record[key] = vuln["extra"]["nvd_data"][0]["cvss_v2"]["vector_string"]
    except TypeError:
        logging.debug(f"no {key}")
        vuln_record[key] = ""

    key = "nvd_cvss_v3_vector"
    try:
        vuln_record[key] = vuln["extra"]["nvd_data"][0]["cvss_v3"]["vector_string"]
    except TypeError:
        logging.debug(f"no {key}")
        vuln_record[key] = ""

    key = "vendor_cvss_v2_vector"
    try:
        for d in vuln["extra"]["vendor_data"]:
            if d["cvss_v2"] and d["cvss_v2"]["vector_string"]:
                vuln_record[key] = d["cvss_v2"]["vector_string"]
    except TypeError:
        logging.debug(f"no {key}")
        vuln_record[key] = ""

    key = "vendor_cvss_v3_vector"
    try:
        for d in vuln["extra"]["vendor_data"]:
            if d["cvss_v3"] and d["cvss_v3"]["vector_string"]:
                vuln_record[key] = d["cvss_v3"]["vector_string"]
    except TypeError:
        logging.debug(f"no {key}")
        vuln_record[key] = ""

    vuln_record["Justification"] = ""
    id = vuln["vuln"] + "-" + vuln["package"]
    if id in justifications.keys():
        vuln_record["Justification"] = justifications[id]

    return vuln_record


def vulnerability_report(csv_dir, anchore_security_json, justifications):
    """
    Generate the anchore vulnerability report

    """
    with open(anchore_security_json, mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
        cves = [
            _vulnerability_record(
                fulltag=json_data["imageFullTag"], justifications=justifications, vuln=d
            )
            for d in json_data["vulnerabilities"]
        ]

    if cves:
        fieldnames = list(cves[0].keys())
    else:
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
            "inherited",
            "description",
            "nvd_cvss_v3_base_score",
            "nvd_cvss_v3_exploitability_score",
            "nvd_cvss_v3_impact_score",
            "nvd_cvss_v2_base_score",
            "nvd_cvss_v2_exploitability_score",
            "nvd_cvss_v2_impact_score",
            "vendor_cvss_v3_base_score",
            "vendor_cvss_v3_exploitability_score",
            "vendor_cvss_v3_impact_score",
            "vendor_cvss_v2_base_score",
            "vendor_cvss_v2_exploitability_score",
            "vendor_cvss_v2_impact_score",
            "Justification",
        ]

    _write_csv_from_dict_list(
        csv_dir=csv_dir,
        dict_list=cves,
        fieldnames=fieldnames,
        filename="anchore_security.csv",
    )

    return len(cves)


# Get results of Anchore gates for csv export, becomes anchore compliance spreadsheet
def compliance_report(csv_dir, anchore_gates_json, justifications):
    with open(anchore_gates_json, encoding="utf-8") as f:
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

        try:
            gate["inherited"] = ad[9]
            if gate["gate"] == "dockerfile":
                gate["inherited"] = False
        except IndexError:
            gate["inherited"] = "no_data"

        cve_justification = ""
        # ad[2] is trigger_id -- e.g. CVE-2020-####
        id = ad[2]
        if ad[4] == "package":
            cve_justification = "See Anchore CVE Results sheet"

        if id in justifications.keys():
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
        "inherited",
        "Justification",
    ]

    _write_csv_from_dict_list(
        dict_list=gates,
        fieldnames=fieldnames,
        filename="anchore_gates.csv",
        csv_dir=csv_dir,
    )

    return {"stop_count": stop_count, "image_id": image_id}


def sbom_report(csv_dir, content_dir):
    return [
        _write_content_csv(csv_dir=csv_dir, content_dir=content_dir, filename=filename)
        for filename in os.listdir(content_dir)
    ]


def _write_content_csv(csv_dir, content_dir, filename):
    with pathlib.Path(content_dir, filename).open(mode="r") as f:
        report_data = json.load(f)

    report_type = report_data["content_type"]

    logging.debug(f"Creating {report_type} CSV.")

    if report_data["content"]:
        fields = list(report_data["content"][0].keys())
        content = report_data["content"]
    else:
        logging.debug(f"{report_type} returned no content data.")
        fields = ["Content"]
        content = [{"Content": f"No content returned for report: {report_type}"}]

    _write_csv_from_dict_list(
        dict_list=content,
        fieldnames=fields,
        filename=f"{report_type}.csv",
        csv_dir=f"{csv_dir}/sbom",
    )
