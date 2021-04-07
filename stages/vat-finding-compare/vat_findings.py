import json
import os
import sys
import logging


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


def check_existence(delta_api_db, api_set, db_set):
    # the following slicing is used to remove description from all the tuples
    db_cve_ids = {f[0:2] + f[3:5] for f in db_set}
    api_cve_ids = {f[0:2] + f[3:5] for f in api_set}
    cve_missing = False
    # check if cve from api exists in db (excluding description)
    for d in {f[0:2] + f[3:5] for f in delta_api_db}:
        if d not in db_cve_ids:
            cve_missing = True
            logging.info("There are inherited CVEs returned by the api that are not returned by query")
            break


def main():
    try:
        with open(
            f'{os.environ["ARTIFACT_STORAGE"]}/lint/vat_api_findings.json', "r"
        ) as api_findings:
            api = json.load(api_findings)
        with open(
            f'{os.environ["ARTIFACT_STORAGE"]}/lint/vat_findings.json', "r"
        ) as db_findings:
            db = json.load(db_findings)
    except FileNotFoundError:
        logging.info("File does not currently exist.")
        sys.exit(3)
    api_set = get_api_findings(api)
    db_set = get_db_findings(db)
    logging.info(f"api set length: {len(api_set)}")
    logging.info(f"db set length: {len(db_set)}")

    if api_set == db_set:
        logging.info("Findings are the same!")
    else:
        delta_api_db = api_set.difference(db_set)
        if delta_api_db:
            logging.info(f"Number of findings in api not in query: {len(delta_api_db)}")
            check_existence(delta_api_db, api_set, db_set)
            logging.info("Findings from api not in direct query")
            for d in delta_api_db:
                logging.info(d)
            diff_art = {
                "api_set_length": len(api_set),
                "db_set_length": len(db_set),
                "delta_api_db": list(delta_api_db),
            }

            with open(f'{os.environ["ARTIFACT_DIR"]}/vat_diff.json', "w") as f:
                json.dump(diff_art, f, indent=4)
            sys.exit(4)
        else:
            logging.info("All findings in api exist in query")


if __name__ == "__main__":
    loglevel = os.environ.get("LOGLEVEL", "INFO").upper()
    if loglevel == "DEBUG":
        logging.basicConfig(
            level=loglevel,
            format="%(levelname)s [%(filename)s:%(lineno)d]: %(message)s",
        )
        logging.debug("Log level set to debug")
    else:
        logging.basicConfig(level=loglevel, format="%(levelname)s: %(message)s")
        logging.info("Log level set to info")
    main()
