#!/usr/bin/env python3
import openpyxl
from openpyxl.styles import Alignment
from openpyxl.utils import get_column_letter
from git import Repo


import git
import os
import shutil
import json
import fnmatch
import sys
import getopt



##### Clone the dccscr-whitelist repository
def cloneWhitelist(whitelistDir, whitelistRepo):
    # Delete the dccscr-whitelist folder (if it exists)
    if os.path.exists(whitelistDir):
        try:
            shutil.rmtree(whitelistDir)
        except OSError as e:
            print("Error: %s : %s" % (whitelistDir, e.strerror))

    # Clone the dccscr-whitelists repo
    git.Git(".").clone(whitelistRepo)


##### Get the greylist for the source image
def getSourceImageGreylistFile(whitelistDir, sourceImage):
    sourceImageGreylistFile = ""
    files = os.listdir(whitelistDir + "/" + sourceImage)
    for file in files:
        if fnmatch.fnmatch(file, "*.greylist"):
            sourceImageGreylistFile = whitelistDir + "/" + sourceImage + '/' + file
            print(sourceImageGreylistFile)
    return sourceImageGreylistFile



##### Get the greylist file for all the base images
def getAllGreylistFiles(whitelistDir, sourceImage, sourceImageGreylistFile):
    # extract base_image from sourceImage .greylist file
    baseImage = ""

    # Add source image greylist file to allFiles
    allFiles.append(sourceImageGreylistFile)

    # Get the image_parent_name from the source image greylist file
    with open(sourceImageGreylistFile) as f:
        try:
            data = json.load(f)
        except ValueError as e:
            print("Error processing file: " + file, file=sys.stderr)
    # Check for empty .greylist file
    if os.stat(sourceImageGreylistFile).st_size == 0:
        print("Source image greylist file is empty")
    # Check for empty image_parent_name in .greylist file
    elif len(data['image_parent_name'])==0:
        print("No parent image")
    else:
        baseImage = data['image_parent_name']

    print("The following base image greylist files have been identified...")

    # Add all parent image greylists to allFiles
    while True:
        files = os.listdir(whitelistDir + "/" + baseImage)
        for file in files:
            if fnmatch.fnmatch(file, "*.greylist"):
                baseImageGreylistFile = whitelistDir + "/" + baseImage + '/' + file
                print(baseImageGreylistFile)
                allFiles.append(baseImageGreylistFile)
                with open(baseImageGreylistFile) as f:
                    try:
                        data = json.load(f)
                    except ValueError as e:
                        print("Error processing file: " + file, file=sys.stderr)
                if os.stat(baseImageGreylistFile).st_size == 0:
                    print("Source image greylist file is empty")
                elif len(data['image_parent_name'])==0:
                    print("No more parent images.")
                else:
                    baseImage = data['image_parent_name']
        # Break loop when it finds the last parent image
        if len(data['image_parent_name'])==0:
            break
    return allFiles



##### Read all greylist files and process into dictionary object
def getJustifications(whitelistDir, allFiles, sourceImageGreylistFile):

    cveOpenscap = {}
    cveTwistlock = {}
    cveAnchore = {}

    # Loop through all the greylist files
    for file in allFiles:
        # Load file into JSON object, print an error if the file doesn't load
        with open(file) as f:
            try:
                data = json.load(f)
            except ValueError as e:
                print("Error processing file: " + file, file=sys.stderr)

        # Check to see if the application is in approved status
        if "approval_status" in data.keys() and data["approval_status"] == "approved":
            # Get a list of all the whitelisted findings
            findings = data["whitelisted_vulnerabilities"]

            # Loop through the findings and create the corresponding dict object based on the vuln_source
            for finding in findings:
                if "vulnerability" in finding.keys():
                    openscapID = finding["vulnerability"]
                    cveID = finding["vulnerability"] + "-" + finding["vuln_description"]

                    # Twistlock finding
                    if finding["vuln_source"] == "Twistlock":
                        if file == sourceImageGreylistFile:
                            cveTwistlock[cveID] = finding["justification"]
                        else:
                            cveTwistlock[cveID] = "Inherited from base image."

                    # Anchore finding
                    elif finding["vuln_source"] == "Anchore":
                        if file == sourceImageGreylistFile:
                            cveAnchore[cveID] = finding["justification"]
                        else:
                            cveAnchore[cveID] = "Inherited from base image."

                    # OpenSCAP finding
                    elif finding["vuln_source"] == "OpenSCAP":
                        if file == sourceImageGreylistFile:
                            cveOpenscap[openscapID] = finding["justification"]
                        else:
                            cveOpenscap[openscapID] = "Inherited from base image."

    return cveOpenscap, cveTwistlock, cveAnchore



##### Process Openscap compliance justifications
def justificationsOpenscap(wb, justifications):
# Process OpenSCAP - DISA Compliance tab
    sheet = wb["OpenSCAP - DISA Compliance"]
    for r in range(1, sheet.max_row+ 1):
        cell = sheet.cell(row = r, column = 5)
        if cell.value == 'identifiers':
            cell = sheet.cell(row = r, column = 10)
            cell.value = "Justification"
        else:
            id = cell.value

            if id in justifications.keys():
                cell = sheet.cell(row = r, column = 10)
                cell.value = justifications[id]



##### Process Twistlock justifications
def justificationsTwistlock(wb, justifications):
# Process Twistlock Vulnerability Results tab
    sheet = wb["Twistlock Vulnerability Results"]
    for r in range(1, sheet.max_row + 1):
        cell = sheet.cell(row = r, column = 1)
        if cell.value == 'id':
            cell = sheet.cell(row = r, column = 10)
            cell.value = "Justification"
        else:
            cell2 = sheet.cell(row = r, column = 3)
            id = cell.value + "-" + cell2.value

            if id in justifications.keys():
                cell = sheet.cell(row = r, column = 10)
                cell.value = justifications[id]

            cell3 = sheet.cell(row = r, column = 5)
            cell4 = sheet.cell(row = r, column = 6)
            id = cell.value + "-" + cell3.value + "-" + cell4.value

            if id in justifications.keys():
                cell = sheet.cell(row = r, column = 10)
                cell.value = justifications[id]



##### Process Anchore justifications
def justificationsAnchore(wb, justifications):
    sheet = wb["Anchore CVE Results"]
    for r in range(1, sheet.max_row + 1):
        cell = sheet.cell(row = r, column = 2)
        if cell.value == 'cve':
            cell = sheet.cell(row = r, column = 8)
            cell.value = "Justification"
        else:
            cell2 = sheet.cell(row = r, column = 4)
            id = cell.value + "-" + cell2.value

            if id in justifications.keys():
                cell = sheet.cell(row = r, column = 8)
                cell.value = justifications[id]


##### Main function
def main(argv):
    # Process command-line arguments
    sourceFile = ""
    outputFile = ""
    sourceImage = ""
    try:
        opts, args = getopt.getopt(argv,"hi:o:s:",["sourcefile=","outputfile=","sourceImage="])
    except getopt.GetoptError:
        print("justifier.py -i <sourceFile> -o <outputfile> -s <sourceImage>")
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print("justifier.py -i <sourceFile> -o <outputfile> -s <sourceImage>")
            sys.exit()
        elif opt in ("-i", "--sourcefile"):
            sourceFile = arg
        elif opt in ("-o", "--outputfile"):
            outputFile = arg
        elif opt in ("-s", "--sourceImage"):
            sourceImage = arg

    print("Source file is " + sourceFile)
    print("Output file is " + outputFile)
    print("Source image is " + sourceImage)

    sourceImageGreylistFile = ""
    global allFiles
    allFiles = []

    # Whitelist directory
    global whitelistDir
    whitelistDir = "dccscr-whitelists"

    # Clone the whitelist repository
    print("Cloning the dccscr-whitelists repository... ", end="", flush=True)
    cloneWhitelist(whitelistDir, "https://repo1.dsop.io/dsop/dccscr-whitelists.git")
    print("done.")

    print("Getting source image greylist... ", end="", flush=True)
    sourceImageGreylistFile = getSourceImageGreylistFile(whitelistDir, sourceImage)
    print("done.")

    print("Getting greylist files for all parent images of " + sourceImage + "\n", end="", flush=True)
    allFiles = getAllGreylistFiles(whitelistDir, sourceImage, sourceImageGreylistFile)
    print("done.")

    # Get all justifications
    print("Gathering list of all justifications... ", end="", flush=True)
    jOpenscap, jTwistlock, jAnchore = getJustifications(whitelistDir, allFiles, sourceImageGreylistFile)
    print("done.")

    # Open the Excel file of the application we are updating
    wb = openpyxl.load_workbook(sourceFile)

    # Apply OpenSCAP compliance justifications
    print("Processing OpenSCAP Compliance Results... ", end="", flush=True)
    justificationsOpenscap(wb, jOpenscap)
    print("done.")

    # Apply Twistlock justifications
    print("Processing Twistlock Vulnerability Results... ", end="", flush=True)
    justificationsTwistlock(wb, jTwistlock)
    print("done.")

    # Apply Anchore justifications
    print("Processing Anchore CVE Results... ", end="", flush=True)
    justificationsAnchore(wb, jAnchore)
    print("done.")



    # Save the Excel file
    wb.save(outputFile)


if __name__ == "__main__":
    main(sys.argv[1:])
