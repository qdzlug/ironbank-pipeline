import os
import json
import pathlib


def get_findings():
    # Get both back and combine them
    cves = _get_full_cve()
    comp = _get_full_compliance()
    full_findings = cves + comp
    return full_findings


def _get_full_cve():
    anchore_file = pathlib.Path(
        os.environ["ARTIFACT_STORAGE"],
        "scan-results",
        "anchore",
        "anchore_security.json",
    )
    with anchore_file.open("r", encoding="utf-8") as af:
        json_data = json.load(af)
        image_tag = json_data["imageFullTag"]
        anchore_data = json_data["vulnerabilities"]
        findings = [
            {
                "source": "anchore_cve",
                "identifier": data["vuln"],
                "package": data["package"],
                "packagePath": data["package_path"],
            }
            for data in anchore_data
        ]
        return findings


def _get_full_compliance():
    anchore_file = pathlib.Path(
        os.environ["ARTIFACT_STORAGE"],
        "scan-results",
        "anchore",
        "anchore_gates.json",
    )
    with anchore_file.open("r", encoding="utf-8") as af:
        json_data = json.load(af)
        sha = list(json_data.keys())[0]
        anchore_data = json_data[sha]["result"]["rows"]
        findings = [
            {
                "source": "anchore_comp",
                "identifier": data[2],
                "package": None,
                "packagePath": None,
            }
            for data in anchore_data
            if data[3] != "vulnerabilities"
        ]
        return findings
