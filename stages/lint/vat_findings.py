import json
import os
from os import read
import sys


def get_api_findings(api):
    api_set = set()
    for finding in api["findings"]:
        api_entry = (
            finding["identifier"],
            finding["source"],
            finding["description"],
            finding["package"] if "package" in finding else None,
            finding["packagePath"] if "packagePath" in finding else None,
        )
        api_set.add(api_entry)
    return api_set


def get_db_findings(db):
    db_set = set()
    for key in db.keys():
        for finding in db[key]:
            db_entry = (
                finding["finding"],
                finding["scan_source"],
                finding["scan_result_description"],
                finding["package"] if "package" in finding else None,
                finding["package_path"] if "package_path" in finding else None,
            )
            db_set.add(db_entry)
    return db_set


def check_existence(delta_api_db, delta_db_api, api_set, db_set):
    # the following slicing is used to remove description from all the tuples
    db_cve_ids = {f[0:2] + f[3:5] for f in db_set}
    api_cve_ids = {f[0:2] + f[3:5] for f in api_set}
    cve_missing = False
    # check if cve from api exists in db (excluding description)
    for d in {f[0:2] + f[3:5] for f in delta_api_db}:
        if d not in db_cve_ids:
            cve_missing = True
            print("There are CVEs from the api that are not returned by the query")
            break
    # check if cve from db exists in api (excluding description)
    for d in {f[0:2] + f[3:5] for f in delta_db_api}:
        if d not in api_cve_ids:
            cve_missing = True
            print("There are CVEs from the query that are not returned by the api")
            break
    if cve_missing:
        print(
            "Please run the development branch for this project before validating query/api data"
        )


def main():
    try:
        with open(
            f'{os.environ["ARTIFACT_DIR"]}/vat_api_findings.json', "r"
        ) as api_findings:
            api = json.load(api_findings)
        with open(f'{os.environ["ARTIFACT_DIR"]}/vat_findings.json', "r") as db_findings:
            db = json.load(db_findings)
    except:
        sys.exit(4)
        
    api_set = get_api_findings(api)
    db_set = get_db_findings(db)
    print(f"api set length: {len(api_set)}")
    print(f"db set length: {len(db_set)}")

    if api_set == db_set:
        print("Findings are the same!")
    else:
        print("Findings are NOT the same!")
        delta_api_db = api_set.difference(db_set)
        delta_db_api = db_set.difference(api_set)
        check_existence(delta_api_db, delta_db_api, api_set, db_set)
        print("Findings from api not in direct query")
        for d in delta_api_db:
            print(d) if delta_api_db else print("None")
        print("Findings from direct query not in api")
        for d in delta_db_api:
            print(d) if delta_db_api else print("None")

        diff_art = {
            "api_set_length": len(api_set),
            "db_set_length": len(db_set),
            "delta_api_db": list(delta_api_db),
            "delta_db_api": list(delta_db_api),
        }

        with open(f'{os.environ["ARTIFACT_DIR"]}/vat_diff.json', "w") as f:
            json.dump(diff_art, f, indent=4)
        sys.exit(4)


if __name__ == "__main__":
    main()
