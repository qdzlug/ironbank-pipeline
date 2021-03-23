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
    delta_api_db = api_set.difference(db_set)
    delta_db_api = db_set.difference(api_set)
    print("Findings from api not in direct query")
    [print(d) for d in delta_api_db] if delta_api_db else print("None")
    print("Findings from direct query not in api")
    [print(d) for d in delta_db_api] if delta_db_api else print("None")
    sys.exit(4)
