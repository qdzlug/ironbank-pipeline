import os
import json
import pathlib


def get_full():
    anchore_file = pathlib.Path(
        os.environ["AS_TEST"],
        "scan-results",
        "anchore",
        "anchore_security.json",
    )
    with anchore_file.open("r", encoding="utf-8") as af:
        json_data = json.load(af)
        image_tag = json_data["imageFullTag"]
        anchore_data = json_data["vulnerabilities"]
        cves = []
        for x in anchore_data:
            tag = image_tag
            cve = x["vuln"]
            severity = x["severity"]
            package = x["package"]
            package_path = x["package_path"]
            fix = x["fix"]
            url = x["url"]

            ret = {
                "tag": tag,
                "cve": cve,
                "severity": severity,
                "package": package,
                "package_path": package_path,
                "fix": fix,
                "url": url,
            }

            cves.append(ret)
        return cves
