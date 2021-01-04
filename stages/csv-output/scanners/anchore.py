#!/usr/bin/env python3

import csv
import json
import pathlib

from scanners.helper import _write_csv_from_dict_list


def _vulnerability_record(fulltag, vuln):

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

    if vuln["nvd_data"] and vuln["nvd_data"][0]["cvss_v3"]:
        vuln_record["nvd_cvss_v3_base_score"] = vuln["nvd_data"][0]["cvss_v3"]["base_score"]
        vuln_record["nvd_cvss_v3_exploitability_score"] = vuln["nvd_data"][0]["cvss_v3"]["exploitability_score"]
        vuln_record["nvd_cvss_v3_impact_score"] = vuln["nvd_data"][0]["cvss_v3"]["impact_score"]
    else:
        vuln_record["nvd_cvss_v3_base_score"] = ""
        vuln_record["nvd_cvss_v3_exploitability_score"] = ""
        vuln_record["nvd_cvss_v3_impact_score"] = ""

    if vuln["nvd_data"] and vuln["nvd_data"][0]["cvss_v2"]:
        vuln_record["nvd_cvss_v2_base_score"] = vuln["nvd_data"][0]["cvss_v2"]["base_score"]
        vuln_record["nvd_cvss_v2_exploitability_score"] = vuln["nvd_data"][0]["cvss_v2"]["exploitability_score"]
        vuln_record["nvd_cvss_v2_impact_score"] = vuln["nvd_data"][0]["cvss_v2"]["impact_score"]
    else:
        vuln_record["nvd_cvss_v2_base_score"] = ""
        vuln_record["nvd_cvss_v2_exploitability_score"] = ""
        vuln_record["nvd_cvss_v2_impact_score"] = ""

    if vuln["vendor_data"] and vuln["vendor_data"][0]["cvss_v3"]:
        vuln_record["vendor_cvss_v3_base_score"] = vuln["vendor_data"][0]["cvss_v3"]["base_score"]
        vuln_record["vendor_cvss_v3_exploitability_score"] = vuln["vendor_data"][0]["cvss_v3"]["exploitability_score"]
        vuln_record["vendor_cvss_v3_impact_score"] = vuln["vendor_data"][0]["cvss_v3"]["impact_score"]
    else:
        vuln_record["vendor_cvss_v3_base_score"] = ""
        vuln_record["vendor_cvss_v3_exploitability_score"] = ""
        vuln_record["vendor_cvss_v3_impact_score"] = ""

    if vuln["vendor_data"] and vuln["vendor_data"][0]["cvss_v2"]:
        vuln_record["vendor_cvss_v2_base_score"] = vuln["vendor_data"][0]["cvss_v2"]["base_score"]
        vuln_record["vendor_cvss_v2_exploitability_score"] = vuln["vendor_data"][0]["cvss_v2"]["exploitability_score"]
        vuln_record["vendor_cvss_v2_impact_score"] = vuln["vendor_data"][0]["cvss_v2"]["impact_score"]
    else:
        vuln_record["vendor_cvss_v2_base_score"] = ""
        vuln_record["vendor_cvss_v2_exploitability_score"] = ""
        vuln_record["vendor_cvss_v2_impact_score"] = ""

    return vuln_record


def vulnerability_report(csv_dir, anchore_security_json):
    """
    Generate the anchore vulnerability report

    """
    with open(anchore_security_json, mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
        cves = [_vulnerability_record(fulltag=json_data["imageFullTag"], vuln=d) for d in json_data["vulnerabilities"]]

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
        ]

    _write_csv_from_dict_list(
        csv_dir=csv_dir,
        dict_list=cves,
        fieldnames=fieldnames,
        filename="anchore_security.csv",
    )

    return len(cves)


def compliance_report(csv_dir, anchore_gates_json):
    """
    Generate the anchore compliance report

    """
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
        csv_dir=csv_dir,
        dict_list=gates,
        fieldnames=fieldnames,
        filename="anchore_gates.csv",
    )
    return {"stop_count": stop_count, "image_id": image_id}
