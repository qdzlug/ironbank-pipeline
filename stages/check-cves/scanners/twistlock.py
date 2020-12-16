import os
import json
import pathlib


def get_full():
    twistlock_file = pathlib.Path(
        os.environ["ARTIFACT_STORAGE"],
        "scan-results",
        "twistlock",
        "twistlock_cve.json",
    )
    with twistlock_file.open(mode="r", encoding="utf-8") as tf:
        json_data = json.load(tf)[0]
        twistlock_data = json_data["vulnerabilities"]
        cves = []
        if twistlock_data is not None:
            for x in twistlock_data:
                cvss = x.get("cvss", "")
                desc = x.get("description", "")
                id = x.get("cve", "")
                link = x.get("link", "")
                packageName = x.get("packageName", "")
                packageVersion = x.get("packageVersion", "")
                severity = x.get("severity", "")
                status = x.get("status", "")
                vecStr = x.get("vecStr", "")
                ret = {
                    "id": id,
                    "cvss": cvss,
                    "desc": desc,
                    "link": link,
                    "packageName": packageName,
                    "packageVersion": packageVersion,
                    "severity": severity,
                    "status": status,
                    "vecStr": vecStr,
                }
                cves.append(ret)
    return cves
