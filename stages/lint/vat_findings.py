import json
import os
from os import read
import sys

def get_api_findings(api):
    api_set = set()
    for finding in api["findings"]:
        api_entry = {
            "id": finding["identifier"],
            "source": finding["source"],
            "desc": finding["description"],
            "package": finding["package"] if "package" in finding else None,
            "package_path": finding["packagePath"] if "packagePath" in finding else None,
        }
        api_set.add(api_entry)
    return api_set

def get_db_findings(db):
    db_set = set()
    for key in db.keys():
        for finding in db[key]:
            db_entry = {
                "id": finding["finding"],
                "source": finding["scan_source"],
                "desc": finding["scan_result_description"],
                "package": finding["package"] if "package" in finding else None,
                "package_path": finding["package_path"] if "package_path" in finding else None,
            }
            db_set.add(db_entry)
    return db_set


def run_issue_check(delta_api_db, delta_db_api, api_set, db_set):
    #Run checks for api - db
    #check existence
    delta_api_db = check_existence(delta_api_db, db_set)
    #first, check if dupes exist for the finding
    # check_duplicates()
    # #check if fields differ for dupes or single value
    # check_different_fields()

    # #Run checks for db - api
    # check_existence()

    # check_duplicates()

    # check_different_fields()


def check_existence(delta, finding_set):
    for i in range(len(delta)):
        # f[0] is the identifier or finding id
        if f[i]["id"] not in [finding["id"] for finding in finding_set]:
            f[i]["Issue"] = "Finding does not exist in other set"




def main():
    with open(f'{os.environ["ARTIFACT_DIR"]}/vat_api_findings.json', "r") as api_findings:
        api = json.load(api_findings)
    with open(f'{os.environ["ARTIFACT_DIR"]}/vat_findings.json', "r") as db_findings:
        db = json.load(db_findings)

    api_set = get_api_findings(api)
    db_set = get_db_findings(db)
    print(f"API set length: {len(api_set)}")
    print(f"DB set length: {len(db_set)}")

    if api_set == db_set:
        print("Findings are the same!")
    else:
        print("Findings are NOT the same!")
        delta_api_db = api_set.difference(db_set)
        delta_db_api = db_set.difference(api_set)
        #delta_api_db, delta_db_api = run_issue_check(delta_api_db, delta_db_api, api_set, db_set)
        print("Findings from api not in direct query")
        for d in delta_api_db:
            print(d) if delta_api_db else print("None")
        print("Findings from direct query not in api")
        for d in delta_db_api:
            print(d) if delta_db_api else print("None")

        diff_art = {
            "api_set_length" : len(api_set),
            "db_set_length" : len(db_set),
            "delta_api_db" : list(delta_api_db),
            "delta_db_api" : list(delta_db_api)
        }
        with open(f'{os.environ["ARTIFACT_DIR"]}/vat_diff.json', 'w') as f:
            json.dump(diff_art, f, indent=4)
        sys.exit(4)


if __name__ == "__main__":
    main()