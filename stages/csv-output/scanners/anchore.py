#!/usr/bin/env python3


import json
from ironbank.pipeline.scan_report_parsers.anchore import AnchoreSecurityParser

from scanners.helper import write_csv_from_dict_list


def vulnerability_report(csv_dir, anchore_security_json, justifications):
    """
    Generate the anchore vulnerability report

    """
    with open(anchore_security_json, mode="r", encoding="utf-8") as f:
        json_data = json.load(f)

    vulns = AnchoreSecurityParser.get_vulnerabilities(json_data)

    vuln_dict_list = []

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
        "nvd_cvss_v2_vector",
        "nvd_cvss_v3_vector",
        "vendor_cvss_v2_vector",
        "vendor_cvss_v3_vector",
        "Justification",
    ]

    for vuln in vulns:
        id = (
            (vuln.cve, vuln.package, vuln.package_path)
            if vuln.package_path != "pkgdb"
            else None
        )
        vuln_dict = {k: v for k, v in vuln.__dict__.items() if k in fieldnames}
        vuln_dict["Justification"] = justifications.get(id, "") or ""

        vuln_dict_list.append(vuln_dict)

    write_csv_from_dict_list(
        csv_dir=csv_dir,
        dict_list=vuln_dict_list,
        fieldnames=fieldnames,
        filename="anchore_security.csv",
    )

    return len(vulns)


def compliance_report(csv_dir, anchore_gates_json, justifications):
    """
    Get results of Anchore gates for csv export, becomes anchore compliance spreadsheet

    """
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
        "inherited",
        "Justification",
    ]

    write_csv_from_dict_list(
        dict_list=gates,
        fieldnames=fieldnames,
        filename="anchore_gates.csv",
        csv_dir=csv_dir,
    )

    return {"stop_count": stop_count, "image_id": image_id}
