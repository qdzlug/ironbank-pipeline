#!/usr/bin/python3

"""
This module loads data into the Database tables from the CSV files.
"""

from pathlib import Path
import argparse
import logging
import logging.handlers
import os
import re
import ast

from datetime import datetime
from datetime import timedelta
import time

import pandas

import mysql.connector
from mysql.connector import Error


parser = argparse.ArgumentParser(description="SQL Agent")
parser.add_argument("-n", "--host", help="Connection Info: Host", required=True)
parser.add_argument(
    "-d", "--db", help="Connection Info: Database to connect to", required=True
)
parser.add_argument("-u", "--user", help="Connection Info: User", required=True)
parser.add_argument(
    "-p",
    "--password",
    default="",
    help="Connection Info: Password, Do not include argument if empty",
)
parser.add_argument(
    "-f", "--csv_dir", help="Path to Directory to all CSV files to parse", required=True
)
parser.add_argument("-j", "--job_id", help="Pipeline job ID", required=True)
parser.add_argument(
    "-sd", "--scan_date", help="scan_date for Jenkins run", required=True
)
parser.add_argument("-c", "--container", help="Container VENDOR/PRODUCT/CONTAINER")
parser.add_argument(
    "-v",
    "--version",
    help="Container Version from VENDOR/PRODUCT/CONTAINER/VERSION format",
)
parser.add_argument("-pc", "--parent", help="Parent VENDOR/PRODUCT/CONTAINER")
parser.add_argument(
    "-pv",
    "--parent_version",
    help="Parent Version from VENDOR/PRODUCT/CONTAINER/VERSION format",
)
parser.add_argument(
    "-sl",
    "--sec_link",
    help="Link to openscap security reports directory",
    required=True,
)
parser.add_argument(
    "-cl",
    "--comp_link",
    help="Link to openscap compliance reports directory",
    required=True,
)
parser.add_argument(
    "-rl",
    "--repo_link",
    help="Link to container repository",
    default="",
    required=False,
)


# This shuts off pandas informational messages for row manipulation
pandas.options.mode.chained_assignment = None


def connect_to_db():
    """
    @return mariadb connection
    """
    conn = None
    try:
        conn = mysql.connector.connect(
            host=args.host, database=args.db, user=args.user, passwd=args.password
        )
        if conn.is_connected():
            # there are many connections to db so this should be uncommented
            # for troubleshooting
            logs.debug("Connected to the host %s with user %s", args.host, args.user)

    except Error as err:
        logs.error(err)
        if conn is not None and conn.is_connected():
            conn.close()

    return conn


def parse_csvs():
    """
    Parse out all csvs files that match token and return dict with all data
    All parsed out csv data will be placed into a uniform dictionary with matching
    column heading for db
    @return dictionary
    """
    data_dict = {}
    csv_dir = Path(args.csv_dir)
    distroless = os.environ.get("DISTROLESS", None)
    if csv_dir.is_dir():
        tl_path = csv_dir.joinpath("tl.csv")
        if tl_path.exists():
            logs.debug("Parsing Twistlock CSV\n")
            remove_lame_header_row(tl_path)
            try:
                data_dict["twistlock_cve"] = parse_twistlock_security(tl_path)
            except Error as error:
                logs.error(f"Failed to parse twistlock \n{error}")
        as_path = csv_dir.joinpath("anchore_security.csv")
        if as_path.exists():
            logs.debug("Parsing Anchore Security CSV\n")
            remove_lame_header_row(as_path)
            try:
                data_dict["anchore_cve"] = parse_anchore_security(as_path)
            except Error as error:
                logs.error(f"Failed to parse anchore cve \n{error}")
        ac_path = csv_dir.joinpath("anchore_gates.csv")
        if ac_path.exists():
            logs.debug("Parsing Anchore Compliance CSV\n")
            remove_lame_header_row(ac_path)
            try:
                data_dict["anchore_comp"] = parse_anchore_compliance(ac_path)
            except Error as error:
                logs.error(f"Failed to parse anchore compliance \n{error}")
        ov_path = csv_dir.joinpath("oval.csv")
        if ov_path.exists() and not distroless:
            logs.debug("Parsing OSCAP Security CSV\n")
            remove_lame_header_row(ov_path)
            try:
                data_dict["oscap_cve"] = parse_oscap_security(ov_path)
            except Error as error:
                logs.error(f"Failed to parse oscap cve \n{error}")
        os_path = csv_dir.joinpath("oscap.csv")
        if os_path.exists() and not distroless:
            logs.debug("Parsing OSCAP Compliance CSV\n")
            remove_lame_header_row(os_path)
            try:
                data_dict["oscap_comp"] = parse_oscap_compliance(os_path)
            except Error as error:
                logs.error(f"Failed to parse oscap compliance \n{error}")
        return data_dict
    else:
        logs.error("\nArgument for csv directory is not a valid directory")
        return False


def parse_anchore_security(as_path):
    """
    @return dataframe with standarized columns for anchore security scan
    """
    anchore_security = pandas.read_csv(as_path)
    # grab the relevant columns we are homogenizing
    d_f = anchore_security[["cve", "severity", "package", "url", "package_path"]]

    # replace pkgdb to None
    d_f.replace({"package_path": {"pkgdb": None}}, inplace=True)

    # copy vuln column to package
    d_f["description"] = d_f["package"]

    d_f.rename(columns={"cve": "finding", "url": "link"}, inplace=True)
    d_f["link"] = d_f["link"].apply(parse_anchore_json)
    d_f["description"] = d_f["description"] + "\n" + d_f["link"]

    # Temporarily Removing imported link and replacing with None
    d_f.drop(columns=["link"], inplace=True)
    d_f = d_f.assign(link=None)

    # REMOVE THIS ONCE PACKAGE PATH FIELD IS ADDED TO DB
    # d_f.drop(columns=["package_path"], inplace=True)

    # needed to add empty row to match twistlock
    d_f = d_f.assign(score="")

    d_f_clean = d_f.where(pandas.notnull(d_f), None)
    logs.debug(f"anchore security dataframe: \n {d_f_clean}")
    return d_f_clean


def parse_twistlock_security(tl_path):
    """
    Creates dataframe  with standarized columns for a twistlock scan
    Return a dataframe
    """

    twistlock = pandas.read_csv(tl_path)

    # grab the relevant columns we are homogenizing
    d_f = twistlock[
        ["id", "severity", "desc", "link", "cvss", "packageName", "packageVersion"]
    ]
    d_f.rename(
        columns={"id": "finding", "desc": "description", "cvss": "score"},
        inplace=True,
    )

    d_f["package"] = d_f["packageName"] + "-" + d_f["packageVersion"]
    d_f.drop(columns=["packageName", "packageVersion"], inplace=True)

    d_f = d_f.assign(package_path=None)

    d_f_clean = d_f.where(pandas.notnull(d_f), None)
    logs.debug(f"twistlock dataframe: \n {d_f_clean}")
    return d_f_clean


def parse_anchore_compliance(ac_path):
    """
    @return dataframe with standarized columns for anchore compliance scan
    """

    d_f = pandas.read_csv(ac_path)

    # This removes the rows where the gate does <> 'vulnerabilities'
    anchore_compliance = d_f[(d_f["gate"] != "vulnerabilities")]

    logs.debug(anchore_compliance)

    # grab the relevant columns we are homogenizing
    d_f = anchore_compliance[
        ["trigger_id", "check_output", "gate_action", "gate", "trigger", "policy_id"]
    ]

    # Prepend the action with "ga_" to distinguish from other severity types
    d_f["gate_action"] = "ga_" + d_f["gate_action"].astype(str)

    d_f.rename(
        columns={
            "trigger_id": "finding",
            "gate_action": "severity",
            "check_output": "description",
        },
        inplace=True,
    )

    d_f["description"] = d_f["description"] + "\n Gate: " + d_f["gate"]
    d_f["description"] = d_f["description"] + "\n Trigger: " + d_f["trigger"]
    d_f["description"] = d_f["description"] + "\n Policy ID: " + d_f["policy_id"]
    d_f.drop(columns=["gate", "trigger", "policy_id"], inplace=True)

    # No link available for this scan
    d_f = d_f.assign(link=None)

    # needed to add empty row to match twistlock
    d_f = d_f.assign(score="")

    # This field is not used by the compliance scans
    d_f = d_f.assign(package=None)

    d_f = d_f.assign(package_path=None)

    d_f_clean = d_f.where(pandas.notnull(d_f), None)
    logs.debug(f"anchore compliance dataframe: \n {d_f_clean}")
    return d_f_clean


def get_packages(package_string):
    """
    Return a list of packages from the input string.
    """

    logs.debug(f"In packages: {package_string}")

    # This will basically remove Updated from an "Updated kernel" package.
    # Capture the package
    # Remove any security, enhancement, bug fix or any combination of those.
    # Match and throw away anything after this up to the severity ().
    initial_re = ".*: (?:Updated )?(.*?)(?:security|enhancement|bug fix).*\\("
    logs.debug(f"packages - perform pattern match {initial_re}")
    match = re.match(initial_re, package_string)

    pkgs = match.group(1) if match else None
    logs.debug(f"After pattern match, pkgs: {pkgs}")

    # Catch all if no packages are found
    if pkgs is None or pkgs.strip(" ") == "":
        pkgs = "Unknown"

    # This will break up multiple packages as a list.
    #   Note: that single packages will be returned as a list.
    pkglist = re.split(", and |, | and ", pkgs.strip(" ").replace(":", "-"))

    logs.debug(f"packages list: {pkglist}")

    return pkglist


def parse_oscap_security(ov_path):
    """
    @return dataframe with standarized columns for OSCAP security scan
    """

    report_link = os.path.join(args.sec_link, "report-cve.html")
    severity_dict = {
        "Critical": "critical",
        "Important": "important",
        "Moderate": "moderate",
        "Low": "low",
        "Unknown": "unknown",
    }

    logs.debug("parse oscap security")
    d_f = pandas.read_csv(ov_path)

    # This keeps the rows where the result is "true" - pandas loads it as a boolean
    oscap_security = d_f[d_f["result"]]

    # grab the relevant columns we are homogenizing
    d_f = oscap_security[["ref", "title"]]

    df_new = oscap_security.title.str.extract(r"\((\w+)\)$", expand=True)
    df_new[0] = df_new[0].apply(lambda x: severity_dict[x])
    d_f["severity"] = df_new[0]

    # Assign the column to a dataframe.
    # Apply the function to the dataframe (single column).
    # Assign the new dataframe as the package column in the dataframe.`
    logs.debug("oscap security - determine package info")
    df_pkg = d_f["title"]
    df_pkg = df_pkg.apply(get_packages)
    d_f["package"] = df_pkg

    d_f.drop(columns=["title"], inplace=True)

    d_f.rename(columns={"ref": "finding"}, inplace=True)

    d_f = d_f.assign(link=report_link)
    d_f = d_f.assign(description="")

    # needed to add empty row to match twistlock
    d_f = d_f.assign(score="")

    d_f = d_f.assign(package_path=None)

    # The following will split into rows by each package in the list.
    # Each row is duplicated with a package in each list.
    df_split = d_f.explode("package").reset_index(drop=True)

    d_f_clean = df_split.where(pandas.notnull(df_split), None)
    logs.debug(f"oscap security dataframe: \n {d_f_clean}")
    return d_f_clean


def parse_oscap_compliance(os_path):
    """
    @return dataframe with standarized columns for OpenSCAP compliance scan
    """

    report_link = os.path.join(args.comp_link, "report.html")
    d_f = pandas.read_csv(os_path)

    # This keeps the rows where the result is fail or notchecked or error
    oscap_compliance = d_f[
        (d_f["result"] == "fail")
        | (d_f["result"] == "notchecked")
        | (d_f["result"] == "error")
    ]

    # grab the relevant columns we are homogenizing
    d_f = oscap_compliance[["severity", "identifiers", "refs", "title"]]

    # This is used where the identifier has not been set in the column (NaN)
    # It will replace these rows with data from the refs column.
    d_f["identifiers"] = d_f.apply(
        lambda x: get_oscap_comp_finding(x["refs"])
        if pandas.isnull(x["identifiers"])
        else x["identifiers"],
        axis=1,
    )

    d_f.drop(columns=["refs"], inplace=True)

    d_f.rename(columns={"identifiers": "finding", "title": "description"}, inplace=True)
    d_f = d_f.assign(link=report_link)

    # needed to add empty row to match twistlock
    d_f = d_f.assign(score="")

    # This field is not used by the compliance scans
    d_f = d_f.assign(package=None)

    d_f = d_f.assign(package_path=None)

    d_f_clean = d_f.where(pandas.notnull(d_f), None)
    logs.debug(f"oscap compliance dataframe: \n {d_f_clean}")
    return d_f_clean


def get_oscap_comp_finding(references):
    """
    Returns a finding from references that matches a regex

    :param references: stringified array of strings
    :return: str
    """
    oscap_finding_regex = re.compile("^OL.*$|^CCE-.*$")
    ref_list = eval(references)
    findings = list(filter(lambda x: oscap_finding_regex.match(x), ref_list))
    finding = findings[0] if findings else ref_list[0]
    return finding


def get_system_user_id(static_user_id=[None]):
    """
    Get the system_user_id from the users table where the username = 'VAT_Bot'.
    Uses the static_user_id variable for the system user ID.
    Is a default parameter that is initially set to None.
    Returns the system_user_id
    """

    logs.debug("In get_system_user_id")

    if not static_user_id[0]:
        try:
            conn = connect_to_db()
            cursor = conn.cursor()
            logs.debug("SELECT id FROM users WHERE username='%s'", "VAT_Bot")
            cursor.execute("SELECT id FROM users WHERE username='VAT_Bot'")
            row = cursor.fetchone()
            if row:
                static_user_id[0] = row[0]
                logs.debug("Found VAT_Bot in users with id: %s", str(static_user_id[0]))
            else:
                logs.warning("No VAT_Bot in users table.")

        except Error as error:
            logs.info(error)
        finally:
            if conn is not None and conn.is_connected():
                conn.close()

    return static_user_id[0]


def find_all_versions(cursor, container_id):
    """
    Gets the id of the last approved container and
    any containers since that did not inherit the approval
    : return dict of approved and unapproved container ids
    """
    valid_states = ["Approved", "Conditionally Approved"]
    approved_versions_query = """
        SELECT c.id, cl.type FROM containers c
        LEFT JOIN (SELECT id, imageid, type from container_log
        WHERE id IN (SELECT MAX(id) FROM container_log GROUP BY imageid)) cl
        ON c.id = cl.imageid WHERE c.name = %s group by c.id;
        """
    cursor.execute(approved_versions_query, (args.container,))
    containers = cursor.fetchall()
    approved_ids = [x[0] for x in containers if x[1] in valid_states]
    unapproved_ids = [x[0] for x in containers if x[1] not in valid_states]
    container_versions = {"approved": approved_ids, "unapproved": unapproved_ids}
    if container_versions["approved"] and container_versions["unapproved"]:
        add_logs = True
    else:
        add_logs = False
    container_versions["add_logs"] = add_logs
    new_version = new_container_version(container_versions, container_id)
    container_versions["new_version"] = new_version
    state = (
        "approved" if container_id in container_versions["approved"] else "unapproved"
    )
    container_versions["state"] = state

    logs.debug(f"Container versions: {container_versions}")

    return container_versions


def new_container_version(versions, container_id):
    """
    Checks if this scan is a version bump
    :param dict of approved and unapproved versions
    :param int container_id to check
    :return bool True if needs approval added
    """
    if container_id in versions["unapproved"] and versions["add_logs"]:
        return True
    return False


def check_container():
    """
    check if a container exists and if it does not create it.
    Update reference to parent_id as well
    @return the container.id from the db and all versions
    """

    conn = connect_to_db()
    cursor = conn.cursor()

    # find parent container and get its id
    parent_id = get_parent_id()
    str_parent_id = str(parent_id) if parent_id else None
    container_id = None
    versions = {}

    if args.repo_link != "":
        repo_link = args.repo_link
        repo_link_health = 1
        ts = time.time()
        repo_link_timestamp = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    query = (
        "INSERT INTO `containers` "
        + "(`id`, `name`, `version`, `parent_id`) "
        + "VALUES (%s, %s, %s, %s) "
        + "ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id), parent_id=%s"
    )

    container_id_tuple = (
        None,
        args.container,
        args.version,
        str_parent_id,
        str_parent_id,
    )

    try:
        logs.debug("Find Container or Add it query:")
        logs.debug(query % container_id_tuple)

        cursor.execute(query, container_id_tuple)
        if cursor.lastrowid:
            logs.debug("Container id from last insert id %s", cursor.lastrowid)
            container_id = cursor.lastrowid
        else:
            # if nothing was updated or inserted we still need to retireve this
            # container id of course their might have been error but lets see if
            # we can get that id
            logs.info("last insert id not found could not find container")
            query = "SELECT * FROM `containers` WHERE name=%s and version=%s"
            cursor.execute(
                query,
                (
                    args.container,
                    args.version,
                ),
            )
            results = cursor.fetchall()
            for row in results:
                container_id = row[0]
                logs.debug("\nFound container with id: %s", str(container_id))

        versions = find_all_versions(cursor, container_id)

        # Update all the containers matching the container name with the repo link
        # info only when the repo link is passed in.
        if args.repo_link != "":
            all_container_ids = versions["approved"] + versions["unapproved"]

            update_query = (
                "UPDATE containers SET link = %s, "
                + "link_health = %s, link_health_timestamp = %s "
                + "WHERE id = %s"
            )
            for cont_id in all_container_ids:
                cursor.execute(
                    update_query,
                    (
                        repo_link,
                        repo_link_health,
                        repo_link_timestamp,
                        cont_id,
                    ),
                )

        conn.commit()

    except Error as error:
        logs.error(error)
        container_id = False
    finally:
        if conn is not None and conn.is_connected():
            conn.close()
    return container_id, versions


def insert_finding(cursor, iid, scan_source, index, row):
    """
    sql to update the finding table from a dataframe row.
    return: id of finding
    """
    logs.debug("Enter insert_finding")

    try:
        # search for an image id and finding in findings approvals table
        # if nothing is returned then insert it
        package_query_string = "="
        package_path_query_string = "="
        if not row["package"]:
            package_query_string = "is"
        if not row["package_path"]:
            package_path_query_string = "is"

        find_parent_finding_query = f"""
            SELECT id FROM `findings` WHERE container_id = %s AND
            finding = %s AND scan_source = %s AND package {package_query_string} %s AND
            package_path {package_path_query_string} %s"""

        cursor.execute(
            find_parent_finding_query,
            (
                iid,
                row["finding"],
                scan_source,
                row["package"],
                row["package_path"],
            ),
        )
        results = cursor.fetchone()
        if results is None:

            logs.debug(
                "inserting new findings values row=%d container_id=%s and "
                + "finding=%s and scan_source=%s and package=%s and package_path=%s",
                index,
                iid,
                row["finding"],
                scan_source,
                row["package"],
                row["package_path"],
            )

            # it doesn't exist so insert it
            cursor.execute(
                """INSERT INTO `findings`
                (`container_id`, `finding`, `scan_source`,
                `package`, `package_path`)
                VALUES (%s, %s, %s, %s, %s)""",
                (
                    iid,
                    row["finding"],
                    scan_source,
                    row["package"],
                    row["package_path"],
                ),
            )
            logs.debug("insert_finding - inserting finding_id: %s", cursor.lastrowid)
            return cursor.lastrowid
        else:
            logs.debug("insert_finding - existing finding_id: %s", results[0])
            return results[0]

    except Error as error:
        logs.error(error)


def insert_finding_scan(cursor, row, finding_id):
    """
    insert a row into the finding_scan_results table
    set that row to active and deactivate last active row
    :params conn mysql connection
    :params row dict of values to insert
    :params finding_id int value of corresponding finding in the findings table
    """
    logs.debug("Starting insert_finding_scan")
    try:
        get_id_query = "SELECT id, job_id FROM `finding_scan_results` WHERE finding_id = %s and active = 1"
        get_id_tuple = (finding_id,)
        logs.debug(get_id_query, get_id_tuple[0])
        cursor.execute(get_id_query, get_id_tuple)
        active_record = cursor.fetchone()
        if active_record and active_record[1] == int(args.job_id):
            return  # duplicate record, retain the record as active
        elif active_record:
            update_sql_query = (
                "UPDATE `finding_scan_results` SET active = 0 WHERE id = %s"
            )

            logs.debug(update_sql_query, active_record[0])
            cursor.execute(update_sql_query, (active_record[0],))

        insert_finding_query = """INSERT INTO `finding_scan_results`
            (`finding_id`, `job_id`, `record_timestamp`, `severity`,
            `link`, `score`, `description`, `active`)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""
        insert_values = (
            finding_id,
            args.job_id,
            args.scan_date,
            row["severity"],
            row["link"],
            row["score"],
            row["description"],
            1,
        )
        logs.debug(insert_finding_query % insert_values)
        cursor.execute(insert_finding_query, insert_values)

    except Error as error:
        logs.error(error)


def clean_up_finding_scan(iid):
    """
    This cleans up the finding_scan_results table for this scan by setting all
    finding_scan_results entries active to 0 which are not part of this job scan
    """

    conn = connect_to_db()
    cursor = conn.cursor(buffered=True)
    try:
        cleanup_query = """
        UPDATE `finding_scan_results` fsr INNER JOIN findings f ON fsr.finding_id = f.id
        SET active = 0 WHERE job_id != %s AND f.container_id = %s
        """
        update_values = (
            args.job_id,
            iid,
        )
        logs.debug(cleanup_query % update_values)
        cursor.execute(cleanup_query, update_values)
    except Error as error:
        logs.error(error)
    finally:
        if conn is not None and conn.is_connected():
            conn.commit()
            conn.close()


def fix_inheritance(cursor, active_records, log_inherited, log_inherited_id):
    """
    Fix incorrect inheritance
    """
    if log_inherited and not log_inherited_id:  # inherited flag but no inherited_id
        logs.debug("Not inherited, updating incorrect flag")
        j_record = (
            [x for x in active_records if x[1] == "justification"]
            if active_records
            else None
        )
        sc_record = (
            [x for x in active_records if x[1] == "state_change"]
            if active_records
            else None
        )
        update_inheritance_query = "UPDATE finding_logs SET inherited = 0 WHERE id = %s"
        if sc_record:
            cursor.execute(update_inheritance_query, (sc_record[0][0],))
        if j_record:
            cursor.execute(update_inheritance_query, (j_record[0][0],))


def update_finding_logs(
    cursor, container_id, row, finding_id, scan_source, lineage, versions
):
    """
    insert a row into the finding_logs table if new or inheritability changes
    if row is inserted,
    set that row to active and deactivate last active row
    :params cursor mysql cursor
    :params container_id int value of corresponding container
    :params row dict of values to insert
    :params finding_id int value of corresponding finding in the findings table
    """

    logs.debug("Starting Update to Findings Log")

    is_finding_inheritable = check_finding_inheritable(row, scan_source)
    bumped_id = find_bumped_id(cursor, row, finding_id, versions, scan_source)

    try:
        system_user_id = get_system_user_id()
        find_log_query = """
            SELECT id, record_type, in_current_scan, active, record_text,
            inherited_id, state, inherited FROM `finding_logs` WHERE
            finding_id = %s AND record_type_active = 1 ORDER BY active desc
            """
        find_log_tuple = (finding_id,)
        logs.debug(find_log_query, finding_id)
        cursor.execute(find_log_query, find_log_tuple)
        active_records = cursor.fetchall()
        log_inherited_id = active_records[0][5] if active_records else None
        log_inherited = active_records[0][7] if active_records else None
        parents = (
            find_parent_findings(cursor, row, lineage, scan_source)
            if lineage and is_finding_inheritable
            else None
        )
        parent_finding = parents[0][0] if parents else None
        log_in_current_scan = active_records[0][2] if active_records else 0
        version_bump_id = None
        j_record = (
            [x for x in active_records if x[1] == "justification"]
            if active_records
            else None
        )
        sc_record = (
            [x for x in active_records if x[1] == "state_change"]
            if active_records
            else None
        )
        active = [x for x in active_records if x[3] == 1] if active_records else None
        if active and active[0][6] == "needs_justification" and bumped_id:
            # Adds in logs if any version previous to this had approvals
            add_approved_logs_for_prev_version(
                cursor, row, versions, scan_source, finding_id, lineage
            )
        fix_inheritance(cursor, active_records, log_inherited, log_inherited_id)
        if active_records and not log_in_current_scan:
            # If not in current_scan in logs update active logs to indicate that it now is in scan
            update_in_current_scan_query = (
                "UPDATE finding_logs SET in_current_scan = 1 WHERE id = %s"
            )
            if sc_record:
                cursor.execute(update_in_current_scan_query, (sc_record[0][0],))
            if j_record:
                cursor.execute(update_in_current_scan_query, (j_record[0][0],))

        if active_records:
            insert_logs_with_logs(
                cursor,
                active_records,
                parent_finding,
                finding_id,
                log_inherited_id,
                is_finding_inheritable,
                versions,
            )
            return True
        if parent_finding:
            insert_logs_with_inheritance(
                cursor,
                parent_finding,
                finding_id,
                version_bump_id,
                is_finding_inheritable,
            )
        else:  # this finding is not inherited
            insert_new_log(cursor, finding_id, system_user_id, is_finding_inheritable)
        return True
    except Error as error:
        logs.error(error)
        return False


def insert_logs_with_logs(
    cursor,
    active_records,
    parent_finding,
    finding_id,
    log_inherited_id,
    is_finding_inheritable,
    versions,
):
    """
    Inserts logs if needed for findings that already have logs.
    """
    logs.debug("Starting function insert_logs_with_logs")
    system_user_id = get_system_user_id()
    version_bump_id = None

    # Clean up of logs where incorrect logs were added
    if not is_finding_inheritable:
        if need_uninherited_log_fix(active_records, versions):
            fix_uninherited_logs(
                cursor, active_records, finding_id, versions, system_user_id
            )
            return True

    if parent_finding:
        match = check_parent_child_match(cursor, finding_id, parent_finding)
        if log_inherited_id == parent_finding and not is_finding_inheritable:
            logs.debug(f"No Inheritance change/log update for {finding_id}")
            insert_logs_with_inheritance(
                cursor,
                parent_finding,
                finding_id,
                version_bump_id,
                is_finding_inheritable,
            )
            [deactivate_log_row(cursor, r[0]) for r in active_records]
            return True
        elif log_inherited_id == parent_finding and match:
            logs.debug("No inheritance change")
            return True  # No change in inherited_id and log state matches
        else:  # Inherits from another parent or inheritance needs to be updated.
            logs.debug(f"Inheritance change/log update for {finding_id}")
            insert_logs_with_inheritance(
                cursor,
                parent_finding,
                finding_id,
                version_bump_id,
                is_finding_inheritable,
            )
            [deactivate_log_row(cursor, r[0]) for r in active_records]
            return True

    elif not log_inherited_id:  # No inherited_id in logs and no parent finding
        logs.debug("Not inherited, no inheritance change")
        return True  # No change in inherited_id

    else:  # no parent finding but has an inherited_id in current logs
        logs.debug(
            f"No parent but has an inherited_id id current logs: {log_inherited_id}"
        )
        [deactivate_log_row(cursor, r[0]) for r in active_records]
        check_log_count_sql = (
            "SELECT COUNT(*) FROM finding_logs WHERE finding_id = %s AND inherited = 0"
        )
        cursor.execute(check_log_count_sql, (finding_id,))
        log_count = cursor.fetchall()[0][0]
        if not log_count:
            insert_new_log(cursor, finding_id, system_user_id, is_finding_inheritable)
        else:
            logs.debug("Reactivating previous logs")
            get_logs = "SELECT record_type, MAX(id) FROM finding_logs WHERE finding_id = %s AND inherited = 0 group by record_type"
            cursor.execute(get_logs, (finding_id,))
            current_logs = cursor.fetchall()
            j_id = (
                [x[1] for x in current_logs if x[0] == "justification"]
                if current_logs
                else None
            )
            sc_id = (
                [x[1] for x in current_logs if x[0] == "state_change"]
                if current_logs
                else None
            )
            # This a rare case, but when we do this itwill look off in the logs since the deactivate will most likely affect
            # the most recent logs. VAT database may need a flag for deactivated rows so we don't pick those up in the display logs.
            if sc_id:
                activate_sc = """
                    UPDATE finding_logs SET active = 1, record_type_active = 1,
                    inherited_id = NULL WHERE id = %s
                    """
                cursor.execute(activate_sc, (sc_id[0],))
                if j_id:
                    activate_j = """
                        UPDATE finding_logs SET active = 0, record_type_active = 1,
                        inherited_id = NULL WHERE id = %s
                        """
                    cursor.execute(activate_j, (j_id[0],))
            else:
                activate_j = """
                    UPDATE finding_logs SET active = 1, record_type_active = 1,
                    inherited_id = NULL WHERE id = %s
                    """
                cursor.execute(activate_j, (j_id,))
        return True


def need_uninherited_log_fix(active_records, versions):
    """
    Check if there's an approved log for an uninherited finding
    where the container is not approved
    """
    if versions["state"] != "approved" and not versions["new_version"]:
        approved_states = ("conditional", "approved")
        if active_records[0][6] in approved_states:
            return True
    return False


def fix_uninherited_logs(cursor, active_records, finding_id, versions, system_user_id):
    """
    Initial fix to remove inheritance logs from findings that should not be approved
    """
    is_finding_inheritable = False
    [deactivate_log_row(cursor, r[0]) for r in active_records]
    insert_fix_log(cursor, finding_id, system_user_id)
    insert_new_log(cursor, finding_id, system_user_id, is_finding_inheritable)


def insert_fix_log(cursor, finding_id, system_user_id):
    """
    Inserts a finding log for a finding with incorrect inherited logs
    :params finding_id int
    :params system_user_id int
    """

    logs.debug("In insert_fix_log")
    record_text = "Previous logs where from parent, but finding requires justifications for current layer"
    # Add log with needs justification
    log_date_time = datetime.strptime(args.scan_date, "%Y-%m-%dT%H:%M:%S")
    log_date_time = log_date_time - timedelta(seconds=5)
    log_date_time_str = log_date_time.strftime("%Y-%m-%dT%H:%M:%S")
    is_finding_inheritable = False

    new_values = (
        None,
        finding_id,
        "justification",  # record_type
        "needs_justification",  # state
        record_text,  # record_text
        1,  # in_current_scan
        None,  # expiration_date
        0,  # inheritable
        None,  # inherited_id
        0,  # inherited
        0,  # false_positive
        system_user_id,  # user_id
        log_date_time_str,  # record_timestamp
        0,  # active
        0,  # record_type_active
    )
    insert_finding_log(cursor, new_values, is_finding_inheritable)


def check_parent_child_match(cursor, finding_id, parent_id):
    """
    Checks if the child finding has the same active logs as the parent.
    If not, adds the two active records to the child.
    """
    logs.debug(
        f"Beginning check_parent_child_match for finding {finding_id} and parent {parent_id}"
    )
    get_logs_query = """
    SELECT finding_id, record_type, state, record_text, expiration_date,
    false_positive, user_id, record_timestamp, active, record_type_active
    FROM finding_logs
    WHERE finding_id in (%s, %s) AND record_type_active = 1 and record_type = "state_change"
    """

    cursor.execute(
        get_logs_query,
        (
            finding_id,
            parent_id,
        ),
    )
    p_c_logs = cursor.fetchall()

    child_sc_log = [log for log in p_c_logs if log[0] == finding_id]
    parent_sc_log = [log for log in p_c_logs if log[0] == parent_id]

    parent_child_match = (
        (child_sc_log[0][2] == parent_sc_log[0][2])
        if parent_sc_log and child_sc_log
        else False
    )

    return parent_child_match


def insert_logs_with_inheritance(
    cursor, parent_finding, finding_id, version_bump_id, is_finding_inheritable
):
    """
    This will insert the logs for the scan that are inherited.
    """

    parent_logs_query = "SELECT * FROM `finding_logs` WHERE finding_id = %s"
    inherting_id = version_bump_id if version_bump_id else parent_finding
    cursor.execute(parent_logs_query, (inherting_id,))
    inherited = 1 if parent_finding else 0
    all_logs = cursor.fetchall()
    for log in all_logs:
        false_positive = 0 if log[10] is None else log[10]
        new_values = (
            None,
            finding_id,
            log[2],  # record_type
            log[3],  # state
            log[4],  # record_text
            1,  # in_current_scan
            log[6],  # expiration_date
            log[7],  # inheritable
            parent_finding,  # inherited_id,
            inherited,  # inherited
            false_positive,  # false_positive
            log[11],  # user_id
            log[12],  # record_timestamp
            log[13],  # active
            log[14],  # record_type_active
        )
        insert_finding_log(cursor, new_values, is_finding_inheritable)


def find_bumped_id(cursor, row, finding_id, versions, scan_source):
    """
    Find the log from the parent version to inherit from
    return version_bump_id
    """
    try:
        logs.debug(f"Entering Find bumped id for {finding_id}")
        versions["approved"].sort(reverse=True)
        bumped_findings = None
        for v in versions["approved"]:
            bumped_findings = find_parent_findings(cursor, row, [v], scan_source)
            if bumped_findings:
                break
        logs.debug(f"Bumped Findings {bumped_findings}")
        if bumped_findings is None:
            return None
        check_status_query = """
        SELECT state from finding_logs where finding_id = %s and active = 1
        """
        cursor.execute(check_status_query, (bumped_findings[0][0],))
        status = cursor.fetchone()
        if status[0] != "needs_justification":
            return bumped_findings[0][0]
    except Error as error:
        logs.error(error)
    return None


def insert_new_log(cursor, finding_id, system_user_id, is_finding_inheritable):
    """
    Inserts a finding log for a new finding with no inherited logs
    :params finding int
    """

    logs.debug("In insert_new_log")

    new_values = (
        None,
        finding_id,
        "state_change",  # record_type
        "needs_justification",  # state
        "",  # record_text
        1,  # in_current_scan
        None,  # expiration_date
        1,  # inheritable
        None,  # inherited_id
        0,  # inherited
        0,  # false_positive
        system_user_id,  # user_id
        args.scan_date,  # record_timestamp
        1,  # active
        1,  # record_type_active
    )
    insert_finding_log(cursor, new_values, is_finding_inheritable)


def insert_finding_log(cursor, values, is_finding_inheritable):
    """
    Insert a new finding_log into finding_logs
    :params values tuple of insert values
    """

    logs.debug("In insert_finding_log")

    # If the finding is not inheritable then set the appropriate fields accordingly
    if not is_finding_inheritable:
        logs.info("Set finding: %s to not inheritable", values[1])
        update_list = list(values)
        update_list[7] = 0  # inheritable
        update_list[8] = None  # inherited_id
        update_list[9] = 0  # inherited
        values = tuple(update_list)

    insert_query = """INSERT INTO `finding_logs` (
        id, finding_id, record_type, state, record_text, in_current_scan, expiration_date,
        inheritable, inherited_id, inherited, false_positive, user_id,
        record_timestamp, active, record_type_active)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
    logs.debug(insert_query % values)
    cursor.execute(insert_query, values)


def deactivate_log_row(cursor, log_id, deactivate=True, deactivate_record_type=True):
    """
    Removes active flag from row defaults to deactivating both active flags
    :params id int
    :returns bool True on success
    """

    logs.debug("In deactivate_log_row")

    active_record_type = 0 if deactivate_record_type else 1
    active_row = 0 if deactivate else 1

    update_query = (
        "UPDATE `finding_logs` SET active = %s, record_type_active = %s WHERE id = %s"
    )

    logs.debug(update_query, active_row, active_record_type, log_id)
    cursor.execute(update_query, (active_row, active_record_type, log_id))


def find_parent_findings(cursor, finding, lineage, scan_source):
    """
    Takes a finding and finds its parent
    :params finding dict
    :params lineage list of parents -
                May be used later to obtain root parent, for now parent is sufficient
    :params scan_source
    :return parents list of tuples with finding id and container id
    """
    package_query_string = "="
    package_path_query_string = "="
    if not finding["package"]:
        package_query_string = "is"
    if not finding["package_path"]:
        package_path_query_string = "is"

    logs.debug(f"find_parent_findings for {finding}")
    logs.debug(f"lineage: {lineage}")

    find_parent_finding_query = f"""SELECT f.id, f.container_id FROM findings f
        INNER JOIN finding_logs fl on f.id = fl.finding_id and fl.active = 1
        WHERE f.finding = %s AND f.scan_source = %s AND f.package {package_query_string} %s
        AND f.package_path {package_path_query_string} %s AND f.container_id = %s
        AND fl.in_current_scan = 1
        """
    for parent in lineage:
        unique_values = (
            finding["finding"],
            scan_source,
            finding["package"],
            finding["package_path"],
            parent,
        )
        logs.debug(find_parent_finding_query % unique_values)
        cursor.execute(find_parent_finding_query, unique_values)
        parents = cursor.fetchall()
        if parents:
            return parents

    return None


def find_lineage(cursor, container_id):
    """
    Retrieves lineage of a child
    :params container_id int
    :return list of parents, grandparents, etc in order
    """

    logs.debug("find_lineage")

    recursive_parent_query = """
        WITH RECURSIVE container_tree as (
        SELECT id, parent_id FROM containers WHERE id = %s
        UNION ALL
        SELECT c.id, c.parent_id
        FROM containers c
            JOIN container_tree AS p ON p.parent_id = c.id
        )
        SELECT id FROM container_tree WHERE id <> %s
        """
    container_id_tuple = (container_id, container_id)
    cursor.execute(recursive_parent_query, container_id_tuple)
    lineage = cursor.fetchall()
    return [t[0] for t in lineage]


def insert_scan(data, iid, scan_source, versions):
    """
    Inserts all scan data into three tables findings, findings_scan_results and finding_logs
    :params data
    :params iid int container_id
    :params scan_source str
    """

    logs.debug("insert_scan")

    if data.empty:
        logs.warning(f"Data for {scan_source} is empty")
        return
    conn = connect_to_db()
    cursor = conn.cursor(buffered=True)
    try:
        lineage = find_lineage(cursor, iid)
        logs.debug(f"show lineage: {lineage}")

        for index, row in data.iterrows():
            finding_id = insert_finding(cursor, iid, scan_source, index, row)
            insert_finding_scan(cursor, row, finding_id)
            if versions["new_version"]:
                logs.debug(f"New Version - Bumping Approval for {args.container}")
                add_approved_logs_for_prev_version(
                    cursor, row, versions, scan_source, finding_id, lineage
                )
            update_finding_logs(
                cursor, iid, row, finding_id, scan_source, lineage, versions
            )

    except Error as error:
        logs.error(error)
    finally:
        if conn is not None and conn.is_connected():
            conn.commit()
            conn.close()


def add_approved_logs_for_prev_version(
    cursor, row, versions, scan_source, finding_id, lineage
):
    """
    This will check if this is the version for this scan has been increased to
    a higher level (bumped version).
    If so then it will add the logs to the bumped level.
    """

    logs.debug("Entering Add Approved Logs")
    version_bump_id = find_bumped_id(cursor, row, finding_id, versions, scan_source)
    parents = find_parent_findings(cursor, row, lineage, scan_source)
    parent_finding = parents[0][0] if parents else None

    if version_bump_id:
        logs.debug("Found Prev Version Finding")
        add_bumped_logs(cursor, row, versions, finding_id, parent_finding, scan_source)


def add_bumped_logs(cursor, row, versions, finding_id, parent_finding, scan_source):
    """
    Adds the finding logs from the previous approved containers to the
    existing container
    """

    is_finding_inheritable = check_finding_inheritable(row, scan_source)

    active_logs_query = """
        SELECT id, record_type, state FROM finding_logs
        WHERE finding_id = %s and record_type_active = 1 AND in_current_scan = 1
        """
    finding_tuple = (finding_id,)
    cursor.execute(active_logs_query, finding_tuple)
    results = cursor.fetchall()

    for line in results:
        state = line[2]
        if line[1] == "state_change" and state in ("conditional", "approved"):
            return

    version_bump_id = find_bumped_id(cursor, row, finding_id, versions, scan_source)
    # Deactivates old finding Logs
    [deactivate_log_row(cursor, r[0]) for r in results]
    insert_logs_with_inheritance(
        cursor, parent_finding, finding_id, version_bump_id, is_finding_inheritable
    )


def check_finding_inheritable(row, scan_source):
    """
    checks and returns if a finding is inheritable
    return True if there is no condition determining the finding is not inheritable
      Condition 1:
        Check if the Anchore compliance gate = 'dockerfile'
        This column is part of the description column in the dataframe
    """

    logs.debug("check_finding_inheritable - scan_source: %s", scan_source)

    if scan_source == "anchore_comp" and "Gate: dockerfile" in row["description"]:
        logs.debug(
            "check_finding_inheritable is NOT inheritable for finding: %s",
            row["finding"],
        )
        return False
    logs.debug(
        "check_finding_inheritable is inheritable for finding: %s", row["finding"]
    )
    return True


def update_in_current_scan(iid, findings, scan_source):
    """
    Check if any findings are no longer in the current scan
    Find all findings in_current_results
    Deactivate in_current_scan logs
    Create new with in_current_scan = 0 logs for all dropped findings
    @param findings dataframe
    @param iid imageid
    @param scan_source current scan type
    """

    logs.debug("In update_in_current_scan")

    conn = connect_to_db()
    cursor = conn.cursor()

    system_user_id = get_system_user_id()
    logs.debug("update_in_current_scan - system_user_id: %s", str(system_user_id))

    try:
        if findings.empty:
            logs.warning(findings)

            # findings (dataframe) is empty
            # This is for the special case where a finding existed and the following
            # run there were no findings for the scan_source so set not in_current_scan
            # for existing findings from previous runs.
            update_not_in_current_scan = """
                UPDATE finding_logs fl INNER JOIN findings f ON fl.finding_id = f.id
                SET fl.in_current_scan=0 WHERE f.container_id =%s and f.scan_source=%s
                """
            logs.debug(update_not_in_current_scan, str(iid), scan_source)
            cursor.execute(
                update_not_in_current_scan,
                (
                    str(iid),
                    scan_source,
                ),
            )
            conn.commit()
            return

        # Query for all the findings for the image ID and the scan source
        select_all_image_scan_source = """
            SELECT f.id FROM findings f
            INNER JOIN finding_logs fl ON f.id = fl.finding_id
            WHERE f.container_id = %s  and f.scan_source = %s and fl.record_type_active = 1
            AND fl.in_current_scan = 1
            """
        logs.debug(select_all_image_scan_source, str(iid), scan_source)
        cursor.execute(
            select_all_image_scan_source,
            (
                str(iid),
                scan_source,
            ),
        )
        all_active_findings = cursor.fetchall()
        active_list = [x[0] for x in all_active_findings]

        select_all_findings_in_scan = """
        SELECT finding_id FROM finding_scan_results fsr
        INNER JOIN findings f ON f.id = fsr.finding_id
        WHERE fsr.job_id = %s AND f.scan_source = %s AND f.container_id = %s
        """
        logs.debug(select_all_findings_in_scan, args.job_id, scan_source, str(iid))
        cursor.execute(
            select_all_findings_in_scan,
            (
                args.job_id,
                scan_source,
                str(iid),
            ),
        )
        all_in_current_scan = cursor.fetchall()
        current_scan_list = [x[0] for x in all_in_current_scan]
        removed_findings = set([x for x in active_list if x not in current_scan_list])
        logs.debug(
            f"Removing in_current_scan for these findings: \n {removed_findings}"
        )
        for finding_id in removed_findings:
            find_log_query = """SELECT id, record_type, in_current_scan,
                active, record_text FROM `finding_logs` WHERE
                finding_id = %s AND record_type_active = 1 ORDER BY active DESC"""
            find_log_tuple = (finding_id,)
            logs.debug(find_log_query, find_log_tuple)
            cursor.execute(find_log_query, find_log_tuple)
            active_logs = cursor.fetchall()
            for r in active_logs:
                logs.debug(f"Removing_current_scan flag for log id: {r[0]}")
                update_not_in_current_scan = """UPDATE finding_logs fl
                SET fl.in_current_scan=0 WHERE fl.id=%s"""
                logs.debug(update_not_in_current_scan, r[0])
                cursor.execute(
                    update_not_in_current_scan,
                    (r[0],),
                )
        conn.commit()

    except Error as error:
        logs.error(error)
        logs.error("dataset:")
        logs.error(error)
    finally:
        if conn is not None and conn.is_connected():
            conn.close()


def is_new_scan(iid):
    """
    @params integer image id
    @return bool true if it is a new scan than exists in DB false otherwise
    check if the scan report we have is new than the current one.
    """
    try:
        conn = connect_to_db()
        cursor = conn.cursor(buffered=True)
        new_scan = False
        if args.job_id is not None and args.scan_date is not None:
            query = """
            SELECT job_id, record_timestamp FROM `finding_scan_results` fsr INNER JOIN `findings` f
            ON fsr.finding_id = f.id WHERE f.container_id = %s order by record_timestamp desc limit 1
            """
            parms = (
                str(iid),
                # args.job_id,
                # args.scan_date,
            )
            cursor.execute(query, parms)
            result = cursor.fetchone()
            logs.debug(result)
            scan_date_datetime = datetime.strptime(args.scan_date, "%Y-%m-%dT%H:%M:%S")
            if result is None:
                new_scan = True
            elif result[0] < int(args.job_id) or result[1] < scan_date_datetime:
                new_scan = True
        else:
            logs.warning(
                "scan date either can not not computed or is older : check params"
            )
    except Error as error:
        logs.error(error)
    finally:
        if conn is not None and conn.is_connected():
            conn.close()
    return new_scan


def get_parent_id(static_parent_id=[None]):
    """
    @params image id
    @return parent id or None if not found
    get parents id with required program parameters
    """

    if not static_parent_id[0]:
        try:
            conn = connect_to_db()
            cursor = conn.cursor()
            # find parent container and get its id
            static_parent_id[0] = None
            if args.parent is not None and args.parent_version is not None:

                query = "SELECT * FROM `containers` WHERE name=%s and version=%s"
                logs.debug(query, args.parent, args.parent_version)
                cursor.execute(
                    query,
                    (args.parent, args.parent_version),
                )
                results = cursor.fetchall()
                for row in results:
                    static_parent_id[0] = row[0]
                    logs.debug("\nFound parent with id: %s", str(static_parent_id[0]))
                    # during a test it was determined that row does not get
                    # populated unless there is a result
            else:
                logs.debug("no parent")
        except Error as error:
            logs.info(error)
        finally:
            if conn is not None and conn.is_connected():
                conn.close()
    return static_parent_id[0]


def push_all_csv_data(data, iid, versions):
    """
    This takes the data dictionary from parsing all csvs and calls insert_scan
    for each entry in the dictionary
    """
    for key in data:
        logs.debug("\n Pushing data set from: %s\n ", key)
        insert_scan(data[key], iid, key, versions)
        update_in_current_scan(iid, data[key], key)


def remove_lame_header_row(mod_me):
    """
    @params string file name to be modified
    Remove the header row if found in csv that contains a bunch of quotes
    """
    with open(mod_me, "r+") as input_file:
        temp = input_file.readline()
        if ",,,," in temp:
            logs.debug("*****************REMOVING HEADER LINE***********************")
            data = input_file.read()  # read the rest
            input_file.seek(0)  # set the cursor to the top of the file
            input_file.write(data)  # write the data back
            input_file.truncate()  # set the file size to the current size


def parse_anchore_json(links):
    """
    @params string of either a url or a list of dicts
    Returns a URL If list, returns string of sources and urls
    """
    try:
        source_list = ast.literal_eval(links)
        link_string = "".join(
            (item["source"] + ": " + item["url"] + "\n") for item in source_list
        )
        return link_string
    except SyntaxError as error:
        logs.info(error)
        return links


def get_last_version(cursor, container_id):
    """
    finds the latst version for the container if it exists
    returns the container_id of the latest version
    """

    logs.debug("In get_last_version, container_id: %s", str(container_id))
    get_container_name = "SELECT name FROM containers WHERE id = %s"
    get_name_tuple = (str(container_id),)
    cursor.execute(get_container_name, get_name_tuple)
    container_name = cursor.fetchone()

    get_version_query = (
        "SELECT id, version FROM containers WHERE name = %s " + "ORDER BY id DESC"
    )
    get_versions_tuple = container_name
    logs.debug(get_version_query % get_versions_tuple)
    cursor.execute(get_version_query, get_versions_tuple)
    versions = cursor.fetchall()
    logs.debug("get_last_version - versions:")
    logs.debug(versions)

    # row 0 is the current container
    version = versions[1][0]
    logs.debug("Last container version %s ", version)
    return version


def set_approval_state(container_id, version):
    """
    This will enter the container log entry for the version update.
    """

    logs.debug("In set_approval_state")

    conn = connect_to_db()
    try:
        cursor = conn.cursor()
        container_list = version["approved"]
        container_list.sort()
        last_container_id = container_list[-1]
        system_user_id = get_system_user_id()
        approved_version_query = """
            SELECT type, expiration_date FROM container_log cl INNER JOIN containers c ON cl.imageid = c.id
            WHERE cl.id in (SELECT MAX(id) FROM container_log WHERE imageid = %s)
            """
        cursor.execute(approved_version_query, (last_container_id,))
        bumped_info = cursor.fetchone()
        bumped_version_status = bumped_info[0]
        bumped_version_exp_date = bumped_info[1]

        get_container_info = "SELECT name, version FROM containers WHERE id = %s"
        get_info_tuple = (str(last_container_id),)
        cursor.execute(get_container_info, get_info_tuple)
        container_info = cursor.fetchone()
        container_name = container_info[0]
        container_version = container_info[1]

        last_log_query = """
        SELECT id, type, text, user_id, date_time, expiration_date FROM container_log WHERE imageid = %s"""
        last_log_tuple = (str(last_container_id),)
        logs.debug(last_log_query % last_log_tuple)
        cursor.execute(last_log_query, last_log_tuple)
        container_logs = cursor.fetchall()
        auto_approval_text = "Auto Approval derived from previous version {}:{}".format(
            container_name, container_version
        )

        insert_log_sql = """
           INSERT INTO container_log (id, imageid, user_id, type, text, date_time, active, expiration_date) VALUES
           (%s, %s, %s, %s, %s, %s, %s, %s)"""
        for log in container_logs:
            container_log_type = log[1]
            container_log_text = log[2]
            container_log_userid = log[3]
            container_log_datetime = log[4]
            container_log_exp_date = log[5]
            insert_log_tuple = (
                None,
                container_id,
                container_log_userid,
                container_log_type,
                container_log_text,
                container_log_datetime,
                0,
                container_log_exp_date,
            )
            logs.debug(insert_log_sql % insert_log_tuple)
            cursor.execute(insert_log_sql, insert_log_tuple)
            conn.commit()
        auto_approve_tuple = (
            None,
            container_id,
            system_user_id,
            bumped_version_status,
            auto_approval_text,
            args.scan_date,
            1,
            bumped_version_exp_date,
        )
        logs.debug(insert_log_sql % auto_approve_tuple)
        cursor.execute(insert_log_sql, auto_approve_tuple)
        conn.commit()

    except Error as error:
        logs.error(f"Error in set_approval_state: {error}")
    finally:
        if conn is not None and conn.is_connected():
            conn.close()


def check_conditional_date(container_id, versions):
    """
    @params int The container id
    This function will fix any containers with a missing expiration date
    If one of the previous versions had an expiration date
    """
    logs.debug("check_conditional_date")
    conn = connect_to_db()
    try:
        cursor = conn.cursor()
        container_state_query = """
        SELECT type, expiration_date FROM container_log cl INNER JOIN containers c ON cl.imageid = c.id
            WHERE cl.id in (SELECT MAX(id) FROM container_log WHERE imageid = %s)
        """
        cursor.execute(container_state_query, (container_id,))
        container_info = cursor.fetchone()
        if (
            container_info
            and container_info[0] == "Conditionally Approved"
            and container_info[1] is None
        ):
            container_list = versions["approved"]
            container_list.sort(reverse=True)
            expiration_date = None
            for c in container_list:
                cursor.execute(container_state_query, (c,))
                version_info = cursor.fetchone()
                if (
                    version_info[0] == "Conditionally Approved"
                    and version_info[1] is not None
                ):
                    expiration_date = version_info[1]
                    break
            if expiration_date:
                logs.debug("Updating Conditional Approval Date")
                update_container_log = """
                UPDATE container_log SET expiration_date = %s
                WHERE id = (SELECT MAX(id) FROM container_log WHERE imageid = %s)
                """
                container_tuple = (
                    expiration_date,
                    container_id,
                )
                cursor.execute(update_container_log, container_tuple)
        conn.commit()
    except Error as error:
        logs.error(f"Error in check_conditional_date: {error}")
    finally:
        if conn is not None and conn.is_connected():
            conn.close()


def main():
    """
    @params the parameters entered from the command line
    Calls the main routine
    """
    if args.parent and get_parent_id() is None:
        logs.warning("The Parent information passed by param does not exist in db.")
        logs.warning("Enter a parent scan to create it")
    data = parse_csvs()
    iid, versions = check_container()
    # false if no imageid found
    if iid and is_new_scan(iid):
        push_all_csv_data(data, iid, versions)
        clean_up_finding_scan(iid)

        if iid in versions["unapproved"] and versions["new_version"]:
            set_approval_state(iid, versions)
        check_conditional_date(iid, versions)

    else:
        logs.warning("newer scan exists not inserting scan report")


if __name__ == "__main__":
    args = parser.parse_args()
    logs = logging.getLogger("findings")
    # Get logging level, set manually when running pipeline
    loglevel = os.environ.get("LOGLEVEL", "INFO").upper()
    if loglevel == "DEBUG":
        logging.basicConfig(
            level=loglevel,
            filename="vat_import_logging.out",
            format="%(levelname)s [%(filename)s:%(lineno)d]: %(message)s",
        )
        logging.debug("Log level set to debug")
    else:
        logging.basicConfig(level=loglevel, format="%(levelname)s: %(message)s")
        logging.info("Log level set to info")
    logs.info("\n*****************************\n\n")
    logs.info("SQL Agent\n\n*****************************\n\n")
    logs.info("Args\n----------------------------")
    logs.info(args)
    logs.info("\n\n")
    main()
    logs.info("Exiting vat_import")
