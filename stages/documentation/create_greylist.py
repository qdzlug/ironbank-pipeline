#!/usr/bin/python3

"""
This module loads data into the Database tables from the approved greylist files.
"""

from pathlib import Path
import argparse
import logging
import logging.handlers
import os
import re
import git
import shutil
import json
import fnmatch
import sys

import pandas
import numpy

import mysql.connector
from mysql.connector import Error


parser = argparse.ArgumentParser(description="SQL Agent")
parser.add_argument("--image", help="Image name", required=True)
parser.add_argument("--tag", help="Image tag", required=True)
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
# parser.add_argument(
#    "-f", "--csv_dir", help="Path to Directory to all CSV files to parse", required=True
# )
# parser.add_argument("-j", "--jenkins", help="Jenkins run number", required=True)
# parser.add_argument("-sd", "--scan_date", help="scan_date for Jenkins run", required=True)
# parser.add_argument("-c", "--container", help="Container VENDOR/PRODUCT/CONTAINER")
# parser.add_argument(
#    "-v", "--version", help="Container Version from VENDOR/PRODUCT/CONTAINER/VERSION format",
# )
# parser.add_argument("-pc", "--parent", help="Parent VENDOR/PRODUCT/CONTAINER")
# parser.add_argument(
#    "-pv", "--parent_version", help="Parent Version from VENDOR/PRODUCT/CONTAINER/VERSION format",
# )
# parser.add_argument("-l", "--link", help="S3 Link to openscap reports directory", required=True)
parser.add_argument("--debug", help="debug true changes log level", action="store_true")

pandas.options.mode.chained_assignment = None


##### Connect to the database
def connect_to_db():
    """
    @return mariadb connection
    """
    conn = None
    try:
        conn = mysql.connector.connect(
            buffered=True,
            host=args.host,
            database=args.db,
            user=args.user,
            passwd=args.password,
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


##### Get container id for --image and --tag arguments
def get_containerId(conn):
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM containers WHERE name = %s AND version = %s",
        (args.image, args.tag),
    )
    row = cursor.fetchone()
    row_count = cursor.rowcount
    if row_count == 1:
        return row[0]
    else:
        print("Image not in database.")


##### Check approval status
def verify_approvalStatus(conn):
    containerId = get_containerId(conn)
    # get the "date_time" for the most recent container_log entry for this image
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT imageId, MAX(date_time) FROM container_log WHERE imageid = %s GROUP BY imageId",
        (containerId,),
    )
    row = cursor.fetchone()
    approved_date = row["MAX(date_time)"]
    # get "type" and container_approved "user_id" for the most recent container_log entry for this image
    cursor.execute(
        "SELECT type, user_id FROM container_log WHERE date_time = %s", (approved_date,)
    )
    row = cursor.fetchone()
    return row["type"], approved_date, row["user_id"]


##### Create greylist.txt file
def create_greylist(conn, approvalStatus, approved_date, user_id):
    containerId = get_containerId(conn)
    print("\n", "approvalStatus =", approvalStatus)
    # get all rows from findings_approvals for this image
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, finding, scan_source, package FROM findings_approvals WHERE imageId = %s",
        (containerId,),
    )
    rows = cursor.fetchall()
    # gather data to jsonData [whitelisted_vulnerabilies] section
    jsonData = {}
    jsonData["whitelisted_vulnerabilities"] = []
    for row in rows:
        vulnerability = row["finding"]
        vuln_description = row["package"]
        vuln_source = row["scan_source"]
        # change the name of the scan_source to match greylist standard naming
        if vuln_source == "twistlock_cve":
            vuln_source = "Twistlock"
        elif vuln_source == "anchore_cve":
            vuln_source = "Anchore"
        elif vuln_source == "anchore_comp":
            vuln_source = "Anchore"
        elif vuln_source == "oscap_cve":
            vuln_source = "OpenSCAP"
        elif vuln_source == "oscap_comp":
            vuln_source = "OpenSCAP"
        status = "approved"
        approval_id = row["id"]
        # get approved_by user's email address
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        approved_by = row["email"]
        # get justification from findings_log table
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT type, MAX(date_time) FROM findings_log WHERE approval_id = %s AND type = 'Justification' GROUP BY type",
            (approval_id,),
        )
        row = cursor.fetchone()
        # If there is a justification, write data to json
        if row:
            approved_date = row["MAX(date_time)"]
            justificationDateTime = row["MAX(date_time)"]
            cursor.execute(
                "SELECT text FROM findings_log WHERE date_time = %s AND approval_id = %s",
                (justificationDateTime, approval_id),
            )
            row = cursor.fetchone()
            justification = row["text"]
            # Write to json
            jsonData["whitelisted_vulnerabilities"].append(
                {
                    "vulnerability": vulnerability,
                    "vuln_description": vuln_description,
                    "vuln_source": vuln_source,
                    "status": status,
                    "approved_date": approved_date,
                    "approved_by": approved_by,
                    "justification": justification,
                }
            )
        else:
            print("approval_id", approval_id, "does not have a justification.")

    # Write .greylist file
    with open("greylist.txt", "w") as outfile:
        json.dump(jsonData, outfile, indent=2, default=str)


def main():
    # Connect to database
    print("Connecting to database...", end="", flush=True)
    conn = connect_to_db()
    print("done.")

    # Verify the image approved
    print("Verifying container approval status...", end="", flush=True)
    approvalStatus, approved_date, user_id = verify_approvalStatus(conn)
    print("Container approval status = ", approvalStatus)
    print("done.")

    # Create greylist file if image approval status is Approve or Conditional
    if approvalStatus == "Approve" or approvalStatus == "Conditional":
        print("Creating .greylist file...", end="", flush=True)
        create_greylist(conn, approvalStatus, approved_date, user_id)
        print("done.")
    else:
        print("Image", args.image, ":", args.tag, "is not approved.")
        sys.exit()


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
