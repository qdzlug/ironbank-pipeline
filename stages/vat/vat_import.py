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
parser.add_argument("-j", "--jenkins", help="Jenkins run number", required=True)
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
    if csv_dir.is_dir():
        tl_path = csv_dir.joinpath("tl.csv")
        if tl_path.exists():
            logs.debug("Parsing Twistlock CSV\n")
            remove_lame_header_row(tl_path)
            try:
                data_dict["twistlock_cve"] = parse_twistlock_security(tl_path)
            except:
                logs.error("Failed to parse twistlock")
        as_path = csv_dir.joinpath("anchore_security.csv")
        if as_path.exists():
            logs.debug("Parsing Anchore Security CSV\n")
            remove_lame_header_row(as_path)
            try:
                data_dict["anchore_cve"] = parse_anchore_security(as_path)
            except:
                logs.error("Failed to parse anchore cve")
        ac_path = csv_dir.joinpath("anchore_gates.csv")
        if ac_path.exists():
            logs.debug("Parsing Anchore Compliance CSV\n")
            remove_lame_header_row(ac_path)
            try:
                data_dict["anchore_comp"] = parse_anchore_compliance(ac_path)
            except:
                logs.error("Failed to parse anchore compliance")
        ov_path = csv_dir.joinpath("oval.csv")
        if ov_path.exists():
            logs.debug("Parsing OSCAP Security CSV\n")
            remove_lame_header_row(ov_path)
            try:
                data_dict["oscap_cve"] = parse_oscap_security(ov_path)
            except:
                logs.error("Failed to parse oscap cve")
        os_path = csv_dir.joinpath("oscap.csv")
        if os_path.exists():
            logs.debug("Parsing OSCAP Compliance CSV\n")
            remove_lame_header_row(os_path)
            try:
                data_dict["oscap_comp"] = parse_oscap_compliance(os_path)
            except:
                logs.error("Failed to parse oscap compliance")
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
    logs.debug("anchore security dataframe:")
    logs.debug(d_f)

    return d_f


def parse_twistlock_security(tl_path):
    """
    Creates dataframe  with standarized columns for a twistlock scan
    Return a dataframe
    """

    twistlock = pandas.read_csv(tl_path)

    # convert severity to high from important
    twistlock.replace(to_replace="important", value="high", regex=True, inplace=True)
    twistlock.replace(to_replace="moderate", value="medium", regex=True, inplace=True)

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

    d_f = d_f.assign(package_path="N/A")

    logs.debug("twistlock dataframe:")
    logs.debug(d_f)

    return d_f


def parse_anchore_compliance(ac_path):
    """
    @return dataframe with standarized columns for anchore compliance scan
    """
    columns = [
        "image_id",
        "repo_tag",
        "trigger_id",
        "gate",
        "trigger",
        "check_output",
        "gate_action",
        "policy_id",
        "matched_rule_id",
        "whitelist_id",
        "whitelist_name",
        "inherited",
    ]

    d_f = pandas.read_csv(ac_path)
    d_f = d_f[columns]

    # Drop bad header row
    d_f = d_f.drop(d_f.index[0])

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
    d_f = d_f.assign(package="N/A")

    d_f = d_f.assign(package_path="N/A")

    logs.debug("anchore compliance dataframe:")
    logs.debug(d_f)

    return d_f


def get_packages(package_string):
    """
    Return a list of packages from the input string.
    """

    logs.debug("In packages: %s", package_string)

    # This will basically remove Updated from an "Updated kernel" package.
    # Capture the package
    # Remove any security, enhancement, bug fix or any combination of those.
    # Match and throw away anything after this up to the severity ().
    initial_re = ".*: (?:Updated )?(.*?)(?:security|enhancement|bug fix).*\\("
    logs.debug("packages - perform pattern match %s", initial_re)
    match = re.match(initial_re, package_string)

    pkgs = match.group(1) if match else None
    logs.debug("After pattern match, pkgs: " + pkgs)

    # Catch all if no packages are found
    if pkgs is None or pkgs.strip(" ") == "":
        pkgs = "Unknown"

    # This will break up multiple packages as a list.
    #   Note: that single packages will be returned as a list.
    pkglist = re.split(", and |, | and ", pkgs.strip(" ").replace(":", "-"))

    logs.debug("packages list: %s", pkglist)

    return pkglist


def parse_oscap_security(ov_path):
    """
    @return dataframe with standarized columns for OSCAP security scan
    """

    report_link = os.path.join(args.sec_link, "report-cve.html")
    severity_dict = {
        "Critical": "critical",
        "Important": "high",
        "Moderate": "medium",
        "Low": "low",
        "Unknown": "low",
    }

    logs.debug("parse oscap security")
    d_f = pandas.read_csv(ov_path)

    # This keeps the rows where the result is "true" - pandas loads it as a boolean
    oscap_security = d_f[d_f["result"] == True]

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

    d_f = d_f.assign(package_path="N/A")

    # The following will split into rows by each package in the list.
    # Each row is duplicated with a package in each list.
    df_split = d_f.explode("package").reset_index(drop=True)

    logs.debug("oscap security dataframe:")
    logs.debug(d_f)

    return df_split


def parse_oscap_compliance(os_path):
    """
    @return dataframe with standarized columns for OSCAP compliance scan
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
    d_f.replace(to_replace="unknown", value="low", regex=True, inplace=True)

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
    d_f = d_f.assign(package="N/A")

    d_f = d_f.assign(package_path="N/A")

    logs.debug("oscap compliance dataframe:")
    logs.debug(d_f)

    return d_f


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


def check_container():
    """
    check if a container exists and if it does not create it. Update reference to parentid as well
    @return the contianer.id from the db
    """
    conn = connect_to_db()
    cursor = conn.cursor()
    # find parent container and get its id
    parent_id = get_parent_id()
    container_id = None
    if parent_id is None:
        query = (
            " INSERT INTO `containers` "
            + "(`id`, `name`, `version`, `parent_id`,`locked_by_user`) VALUES ( NULL,  '"
            + args.container
            + "',  '"
            + args.version
            + "',  NULL, NULL) ON DUPLICATE KEY UPDATE parent_id=NULL"
        )
    else:
        query = (
            " INSERT INTO `containers` "
            + "(`id`, `name`, `version`, `parent_id`, `locked_by_user`) VALUES ( NULL,  '"
            + args.container
            + "',  '"
            + args.version
            + "',  '"
            + str(parent_id)
            + "', NULL) ON DUPLICATE KEY UPDATE parent_id='"
            + str(parent_id)
            + "'"
        )
    try:
        logs.debug("Find Container or Add it query:%s\n", query)

        cursor.execute(query)
        if cursor.lastrowid:
            logs.debug("Container id from last insert id %s", cursor.lastrowid)
            container_id = cursor.lastrowid
        else:
            # if nothing was updated or inserted we still need to retireve this
            # container id of course their might have been error but lets see if
            # we can get that id
            logs.info("last insert id not found could not find container")
            query = (
                "SELECT * FROM `containers` WHERE name='"
                + args.container
                + "' and version='"
                + args.version
                + "'"
            )
            cursor.execute(query)
            results = cursor.fetchall()
            for row in results:
                container_id = row[0]
                logs.debug("\nFound container with id: %s", str(container_id))
        conn.commit()
    except Error as error:
        logs.error(error)
        container_id = False
    finally:
        if conn is not None and conn.is_connected():
            conn.close()
    return container_id


def insert_scan(data, iid, scan_source):
    """
    sql to iterate through a parsed csv file and update appropriately.
    Twistlock is the only dictionary with an extra column,
    a check for that type of data is included and all the rest work
    the same by this point in processing
    ##for each element in data
    ### check if image scanned already exists ? enter into images table and
        retrieve imageid: retrieve imageid
    ### insert into scan results table with imageid
    ### check cve_approval that cveid and imageid exists ?
        create new entry in cve_approvals : no op
    """

    logs.debug("insert_scan")

    if data.empty:
        logs.warning(data)
        return
    conn = connect_to_db()
    try:
        for index, row in data.iterrows():
            cursor = conn.cursor(buffered=True)
            cursor.execute(
                "INSERT INTO `scan_results`"
                + "(`id`, `imageid`, `finding`, `jenkins_run`, `scan_date`, "
                + "`scan_source`, `severity`, `link`, `score`, `description`, "
                + "`package`, `package_path`)"
                + " VALUES (NULL,'"
                + str(iid)
                + "', '"
                + row["finding"]
                + "', '"
                + str(args.jenkins)
                + "', '"
                + args.scan_date
                + "', %s, %s, %s, %s, %s, %s, %s)",
                (
                    scan_source,
                    row["severity"],
                    row["link"],
                    row["score"],
                    row["description"],
                    row["package"],
                    row["package_path"],
                ),
            )

            # search for an image id and finding in findings approvals table
            # if nothing is returned then insert it
            cursor.execute(
                "SELECT id FROM `findings_approvals` WHERE "
                + "imageid=%s and finding=%s and scan_source=%s and "
                + "package=%s and package_path=%s",
                (iid, row["finding"], scan_source, row["package"], row["package_path"]),
            )
            logs.debug(
                "inserting new findings values row=%d imageid=%s and finding=%s and scan_source=%s and package=%s and package_path=%s",
                index,
                iid,
                row["finding"],
                scan_source,
                row["package"],
                row["package_path"],
            )
            results = cursor.fetchone()
            if results is None:

                # it doesn't exist so insert it
                cursor.execute(
                    "INSERT INTO `findings_approvals` "
                    + "(`imageid`, `finding`, `is_inheritable`, `scan_source`, "
                    + "`package`, `package_path`)"
                    + "VALUES (%s, %s, '1', %s, %s, %s)",
                    (
                        iid,
                        row["finding"],
                        scan_source,
                        row["package"],
                        row["package_path"],
                    ),
                )
    except Error as error:
        logs.error(error)
    finally:
        if conn is not None and conn.is_connected():
            conn.commit()
            conn.close()


def update_inheritance_id(findings):
    """
    @params int image id
    @params dataframe with all the findings that are inheritable and the id they are associated with
    """
    logs.debug("insert_scan")
    parent_id = get_parent_id()
    # this would have been checked when generating the findings but just in case check again
    try:
        conn = connect_to_db()
        cursor = conn.cursor(buffered=True)
        if parent_id is None:
            logs.info("no parent exists")
            for i, row in findings.iterrows():
                # Resets inherited id to NULL if finding is not inherited
                logs.debug("Resetting inheritance for approval_id " + (str(row["id"])))
                sql = "UPDATE `findings_approvals` SET inherited_id=NULL WHERE id= %s"
                params = (row["id"],)
                cursor.execute(sql, params)
                # Deletes Inherited Log
                sql = "DELETE FROM `findings_log` WHERE `approval_id` = %s and `type` =  'Inherited'"
                params = (row["id"],)
                cursor.execute(sql, params)
        else:
            for i, row in findings.iterrows():
                sql = (
                    """SELECT id FROM `findings_approvals` WHERE imageid= %s
                    and scan_source = %s and finding = %s and package = %s
                    and package_path = %s"""
                )
                params = (parent_id,
                row["scan_source"],
                row["finding"],
                row["package"],
                row["package_path"],)

                cursor.execute(sql, params)
                result = cursor.fetchone()
                if result is not None:
                    logs.debug("Updating inherited_id for %s", (str(row["id"])))
                    cursor.execute(
                        "UPDATE `findings_approvals` SET inherited_id=%s WHERE id=%s",
                        (result[0], row["id"]),
                    )

                    sql = (
                        """SELECT * FROM `findings_log` WHERE `approval_id` = %s
                        AND `type` = 'Inherited'"""
                    )
                    params = (row["id"],)
                    cursor.execute(sql, params)
                    i_finding = cursor.fetchone()
                    if i_finding is None:
                        vat_user_query = "SELECT id from users where username = 'legacy_container_contributor'"
                        cursor.execute(vat_user_query)
                        vat_user = cursor.fetchone()[0]
                        sql = """INSERT INTO `findings_log` (`approval_id`, `date_time`, `user_id`, `type`, `text`)
                            VALUES (%s, NOW(), %s, 'Inherited', 'Inherited from parent')"""
                        params = (
                            row["id"],
                            vat_user,
                        )
                        cursor.execute(sql, params)
                else:
                    # Resets inherited id to NULL if finding is not inherited
                    logs.debug(
                        "Resetting inheritance for approval_id " + (str(row["id"]))
                    )
                    cursor.execute(
                        "UPDATE `findings_approvals` SET inherited_id=NULL WHERE id="
                        + str(row["id"])
                    )
                    # Deletes Inherited Log
                    sql = (
                        "DELETE FROM `findings_log` "
                        + "WHERE `approval_id` = "
                        + (str(row["id"]))
                        + " and `type` =  'Inherited'"
                    )
                    cursor.execute(sql)

        conn.commit()
    except Error as error:
        logs.error(error)
    finally:
        if conn is not None and conn.is_connected():
            conn.close()


def update_in_current_scan(iid, findings, scan_source):
    """
    check if any findings are no longer in the current scan
    we are going to reset all the in_current_results to 1 and
    then flip the findings not in the current scan (dataframe)
    @param findings dataframe
    @param iid imageid
    @param scan_source current scan type
    """

    conn = connect_to_db()
    if findings.empty:
        logs.warning(findings)

        # This is for the special case where a finding existed and the following
        # run there were no findings for the scan_source so set not in_current_scan
        # for existing findings from previous runs.
        cursor = conn.cursor()
        sql = (
            "UPDATE `findings_approvals` SET in_current_scan=0 WHERE imageid="
            + str(iid)
            + " and scan_source='"
            + scan_source
            + "'"
        )
        logs.debug("Executing %s", sql)
        cursor.execute(sql)
        conn.commit()
        return

    try:

        # Set all the findings to 1 for the image ID and the scan source
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE `findings_approvals` "
            + "SET in_current_scan=1  WHERE imageid=%s  and scan_source=%s",
            (iid, scan_source),
        )

        # Query for all the findings for the image ID and the scan source
        cursor.execute(
            "SELECT id, finding, package, package_path FROM "
            + "`findings_approvals` WHERE imageid=%s and scan_source=%s",
            (iid, scan_source),
        )

        # Load the query into a dataframe
        d_f = pandas.DataFrame(cursor.fetchall())
        if not d_f.empty:
            d_f.columns = cursor.column_names

            # Remove the current scan from all the findings list
            for i, row in findings.iterrows():
                d_f.drop(
                    d_f[
                        (d_f["finding"] == row["finding"])
                        & (d_f["package"] == row["package"])
                        & (d_f["package_path"] == row["package_path"])
                    ].index,
                    inplace=True,
                )

            # Loop for the remaining rows which are not in the current scan
            logs.debug(d_f)
            for i, row in d_f.iterrows():

                # Set the finding to not in scan
                sql = (
                    "UPDATE `findings_approvals` SET in_current_scan=0 WHERE id="
                    + str(row["id"])
                )
                logs.debug("For row=%d, Executing %s", i, sql)
                cursor.execute(sql)

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
    @return bool true if it is a new scan than exists in db false otherwise
    check if the scan report we have is new than the current one.
    """
    try:
        conn = connect_to_db()
        cursor = conn.cursor(buffered=True)
        new_scan = False
        if args.jenkins is not None and args.scan_date is not None:
            query = (
                "SELECT * FROM `scan_results` WHERE imageid='"
                + str(iid)
                + "' and  (jenkins_run >= '"
                + args.jenkins
                + "' or scan_date > '"
                + args.scan_date
                + "')"
            )
            cursor.execute(query)
            result = cursor.fetchone()
            if result is None:
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


def get_parent_id():
    """
    @params image id
    @return parent id or none if not found
    get parents id with required program parameters
    """
    try:
        conn = connect_to_db()
        cursor = conn.cursor()
        # find parent container and get its id
        parent_id = None
        if args.parent is not None and args.parent_version is not None:
            query = (
                "SELECT * FROM `containers` WHERE name='"
                + args.parent
                + "' and version='"
                + args.parent_version
                + "'"
            )
            cursor.execute(query)
            results = cursor.fetchall()
            for row in results:
                parent_id = row[0]
                logs.debug("\nFound parent with id: %s", str(parent_id))
                # during a test it was determined that row does not get
                # populated unless there is a result
        else:
            logs.debug("no parent")
    except Error as error:
        logs.info(error)
    finally:
        if conn is not None and conn.is_connected():
            conn.close()
    return parent_id


def get_all_inheritable_findings(iid):
    """
    @param image id
    @return dataframe with all findings asscoiated with a container that are inhreitable
    """
    try:
        conn = connect_to_db()
        cursor = conn.cursor()
        parent_id = get_parent_id()
        sql = (
            "SELECT id, finding, scan_source, package, package_path FROM findings_approvals WHERE is_inheritable=1 and imageid="
            + str(iid)
        )
        cursor.execute(sql)
        logs.debug(sql)
        d_f = pandas.DataFrame(cursor.fetchall())
        if not d_f.empty:
            d_f.columns = cursor.column_names
        logs.debug("print all findings that are inheritable and not inherited yet\n")
        logs.debug("----------------------------")
        logs.debug(d_f)
        return d_f
    except Error as error:
        logs.error(error)
    finally:
        if conn is not None and conn.is_connected():
            conn.close()


def push_all_csv_data(data, iid):
    """
    This takes the data dictionary from parsing all csvs and calls insert_scan
    for each entry in the dictionary
    """
    for key in data:
        logs.debug("\n Pushing data set from: %s\n ", key)
        insert_scan(data[key], iid, key)
        update_in_current_scan(iid, data[key], key)


def remove_lame_header_row(mod_me):
    """
    @params string file name to be modified
    Remove the header row if found in csv that contains a bunch of quotes
    """
    with open(mod_me, "r+") as input_file:
        temp = input_file.readline()
        # if "'','','',''," in temp:
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
    except:
        return links


def main():
    """
    @params the parameters entered from the command line
    Calls the main routine
    """
    if args.parent and get_parent_id() is None:
        logs.warning("The Parent information passed by param does not exist in db.")
        logs.warning("Enter a parent scan to create it")
    data = parse_csvs()
    iid = check_container()
    # false if no imageid found
    if iid and is_new_scan(iid):
        push_all_csv_data(data, iid)
        d_f = get_all_inheritable_findings(iid)
        update_inheritance_id(d_f)
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
