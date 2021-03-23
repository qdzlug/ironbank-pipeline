import json
import os
from os import read
import sys

# Pulled from most recent ubi8 test pipeline run 3/23/201 9:00 AM EDT
with open(f'{os.environ["ARTIFACT_DIR"]}/vat_api_findings.json', "r") as api_findings:
    api = json.load(api_findings)
with open(f'{os.environ["ARTIFACT_DIR"]}/vat_findings.json', "r") as db_findings:
    db = json.load(db_findings)

i = 0
j = 0
api_list = []
db_list = []

for finding in api["findings"]:
    api_entry = (
        finding["identifier"],
        finding["source"],
        finding["description"],
        finding["package"] if "package" in finding else None,
        finding["packagePath"] if "packagePath" in finding else None,
    )
    if api_entry not in api_list:
        api_list.append(api_entry)

for finding in db[list(db.keys())[0]]:
    db_entry = (
        finding["finding"],
        finding["scan_source"],
        finding["scan_result_description"],
        finding["package"] if "package" in finding else None,
        finding["package_path"] if "package_path" in finding else None,
    )
    if db_entry not in db_list:
        db_list.append(db_entry)
    j += 1


if api_list == db_list:
    print("Findings are the same!")
else:
    print("Findings are NOT the same!")
    delta = api_list.difference(db_list)
    [print(d) for d in delta]
    sys.exit(4)
