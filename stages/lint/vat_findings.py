import json
import os
from os import read
import sys

# Pulled from most recent ubi8 test pipeline run 3/23/201 9:00 AM EDT
with open(f'./vat_api_findings.json', "r") as api_findings:
    api = json.load(api_findings)
with open(f'./vat_findings.json', "r") as db_findings:
    db = json.load(db_findings)

i = 0
j = 0
api_set = set()
db_set = set()

for finding in api["findings"]:
    api_entry = (
        finding["identifier"],
        finding["source"],
        finding["description"],
        finding["package"] if "package" in finding else None,
        finding["packagePath"] if "packagePath" in finding else None,
    )
    api_set.add(api_entry)

for finding in db[list(db.keys())[0]]:
    db_entry = (
        finding["finding"],
        finding["scan_source"],
        finding["scan_result_description"],
        finding["package"] if "package" in finding else None,
        finding["package_path"] if "package_path" in finding else None,
    )

    db_set.add(db_entry)
    j += 1


if api_set == db_set:
    print("Findings are the same!")
else:
    print("Findings are NOT the same!")
    delta = api_set.difference(db_set)
    [print(d) for d in delta]
    sys.exit(4)
