#!/usr/bin/env python3

import csv
import json
import pathlib

from scanners.helper import _write_csv_from_dict_list


# ANCHORE SECURITY CSV
def vulnerability_report(csv_dir, anchore_security_json):
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
        csv_dir=csv_dir,
        dict_list=cves,
        fieldnames=fieldnames,
        filename="anchore_security.csv",
    )

    return len(cves)


# ANCHORE GATES CSV
def compliance_report(csv_dir, anchore_gates_json):
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
