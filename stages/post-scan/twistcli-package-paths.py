import sys
import json
from itertools import groupby


def get_package_paths(twistlock_data):
    """
    Return a dict of (package_name, package_path) mapped to a list of paths.
    """

    def packages():
        # Often go versions of binaries are in "applications"
        if "applications" in twistlock_data:
            yield from twistlock_data["applications"]

        # Python/RPM/Go/etc package versions are in "packages"
        yield from twistlock_data["packages"]

    # Sort and group by name and version
    keyfunc = lambda x: (x["name"], x["version"])

    return {
        k: {p.get("path", None) for p in packages}
        for k, packages in groupby(sorted(packages(), key=keyfunc), key=keyfunc)
    }


def get_vulnerabilities(twistlock_data):
    """
    Convert the the Twistlock API JSON response to the VAT import format.
    """

    packages = get_package_paths(twistlock_data)

    for v in twistlock_data["vulnerabilities"]:
        key = v["packageName"], v["packageVersion"]
        for path in packages.get(key, [None]):
            yield {
                "finding": v["id"],
                "severity": v["severity"],
                "description": v.get("description"),
                "link": v["link"],
                "score": v.get("cvss"),
                "package": f"{v['packageName']}-{v['packageVersion']}",
                "packagePath": path,
                "scan_source": "twistlock_cve",
            }


twistlock_cve_path = sys.argv[1]  # twistlock_cve.json
with open(twistlock_cve_path) as f:
    twistlock_data = json.load(f)["results"][0]

json.dump(list(get_vulnerabilities(twistlock_data)), sys.stdout, indent=4)
print()
