#!/usr/bin/env python3
import openpyxl
from openpyxl.styles import Alignment, PatternFill
from openpyxl.utils import get_column_letter

import git
import os
import shutil
import json
import fnmatch
import sys
import getopt

##### The InheritableTriggerIds variable contains a list of Anchore compliance trigger_ids
##### that are inheritable by child images.
inheritableTriggerIds = [
    '639f6f1177735759703e928c14714a59',
    'c2e44319ae5b3b040044d8ae116d1c2f',
    '698044205a9c4a6d48b7937e66a6bf4f',
    '463a9a24225c26f7a5bf3f38908e5cb3',
    'bcd159901fe47efddae5c095b4b0d7fd',
    '320a97c6816565eedf3545833df99dd0',
    '953dfbea1b1e9d5829fbed2e390bd3af',
    'e7573262736ef52353cde3bae2617782',
    'addbb93c22e9b0988b8b40392a4538cb',
    '3456a263793066e9b5063ada6e47917d',
    '3e5fad1c039f3ecfd1dcdc94d2f1f9a0',
    'abb121e9621abdd452f65844954cf1c1',
    '34de21e516c0ca50a96e5386f163f8bf',
    'c4ad80832b361f81df2a31e5b6b09864'
]


##### Clone the dccscr-whitelist repository
def cloneWhitelist(whitelistDir, whitelistRepo):
    # Delete the dccscr-whitelist folder (if it exists)
    if os.path.exists(whitelistDir):
        try:
            shutil.rmtree(whitelistDir)
        except OSError as e:
            print("Error: %s : %s" % (whitelistDir, e.strerror))

    # Clone the dccscr-whitelists repo
    dccscrWhitelistBranch = os.getenv("WL_TARGET_BRANCH")
    # Clone the dccscr-whitelists repo
    git.Repo.clone_from(whitelistRepo, os.path.join('./', 'dccscr-whitelists'), branch=dccscrWhitelistBranch)



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
                    trigger_id_inherited = finding["vulnerability"]
                    trigger_id = finding["vulnerability"]

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
                            cveAnchore[trigger_id] = finding["justification"]
                        else:
                            cveAnchore[cveID] = "Inherited from base image."
                            if trigger_id in inheritableTriggerIds:
                                cveAnchore[trigger_id] = "Inherited from base image."


                    # OpenSCAP finding
                    elif finding["vuln_source"] == "OpenSCAP":
                        if file == sourceImageGreylistFile:
                            cveOpenscap[openscapID] = finding["justification"]
                        else:
                            cveOpenscap[openscapID] = "Inherited from base image."
            #print(cveAnchore)
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
            cell_justification = sheet.cell(row = r, column = 10)

            if id in justifications.keys():
                cell_justification.value = justifications[id]

            # Apply appropriate highlighting to justification cell
            if cell_justification.value == None:
                cell_justification.fill = PatternFill(fill_type=None)
            elif cell_justification.value == 'Inherited from base image.':
                cell_justification.fill = PatternFill(start_color='0000b050', end_color='0000b050', fill_type='solid')
            else:
                cell_justification.fill = PatternFill(start_color='0000b0f0', end_color='0000b0f0', fill_type='solid')



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
            cell_justification = sheet.cell(row = r, column = 10)
            if cell2.value == None:
                id = cell.value
            else:
                id = cell.value + "-" + cell2.value

            if id in justifications.keys():
                cell_justification.value = justifications[id]

            cell3 = sheet.cell(row = r, column = 5)
            cell4 = sheet.cell(row = r, column = 6)
            id = cell.value + "-" + cell3.value + "-" + cell4.value

            if id in justifications.keys():
                cell_justification.value = justifications[id]

            # Apply appropriate highlighting to justification cell
            if cell_justification.value == None:
                cell_justification.fill = PatternFill(start_color='00ffff00', end_color='00ffff00', fill_type='solid')
            elif cell_justification.value == 'Inherited from base image.':
                cell_justification.fill = PatternFill(start_color='0000b050', end_color='0000b050', fill_type='solid')
            else:
                cell_justification.fill = PatternFill(start_color='0000b0f0', end_color='0000b0f0', fill_type='solid')



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
            cell_justification = sheet.cell(row = r, column = 8)
            id = cell.value + "-" + cell2.value

            if id in justifications.keys():
                cell_justification.value = justifications[id]

            # Apply appropriate highlighting to justification cell
            if cell_justification.value == None:
                cell_justification.fill = PatternFill(start_color='00ffff00', end_color='00ffff00', fill_type='solid')
            elif cell_justification.value == 'Inherited from base image.':
                cell_justification.fill = PatternFill(start_color='0000b050', end_color='0000b050', fill_type='solid')
            else:
                cell_justification.fill = PatternFill(start_color='0000b0f0', end_color='0000b0f0', fill_type='solid')



##### Process Anchore compliance justifications
def justificationsAnchoreComp(wb, justifications, inheritableTriggerIds):
    sheet = wb["Anchore Compliance Results"]
    for r in range(1, sheet.max_row + 1):
        cell = sheet.cell(row = r, column = 3)
        if cell.value == 'trigger_id':
            cell = sheet.cell(row = r, column = 12)
            cell.value = "Justification"
        else:
            cell2 = sheet.cell(row = r, column = 5)
            cell_justification = sheet.cell(row = r, column = 12)
            if cell2.value == 'package':
                cell_justification.value = "See Anchore CVE Results sheet"

            id = cell.value
            if id in justifications.keys():
                cell_justification.value = justifications[id]

            # Apply appropriate highlighting to justification cell
            if cell_justification.value == None:
                cell_justification.fill = PatternFill(start_color='00ffff00', end_color='00ffff00', fill_type='solid')
            elif cell_justification.value == 'Inherited from base image.':
                cell_justification.fill = PatternFill(start_color='0000b050', end_color='0000b050', fill_type='solid')
            elif cell_justification.value == 'See Anchore CVE Results sheet':
                cell_justification.fill = PatternFill(start_color='96969696', end_color='96969696', fill_type='solid')
            else:
                cell_justification.fill = PatternFill(start_color='0000b0f0', end_color='0000b0f0', fill_type='solid')



def setColumnWidth(sheet, column, width, wrap=False):
    """Set column width and enable text wrap"""
    sheet.column_dimensions[get_column_letter(column)].width = width
    if wrap:
        for cell in sheet[get_column_letter(column)]:
            cell.alignment = Alignment(wrap_text=True)



def setAllColumnWidths(wb):

    openscap_disa = wb["OpenSCAP - DISA Compliance"]
    setColumnWidth(openscap_disa, column=9, width=20) # scanned_date
    setColumnWidth(openscap_disa, column=10, width=30) # justification

    twistlock = wb["Twistlock Vulnerability Results"]
    setColumnWidth(twistlock, column=1, width=25) # CVE
    setColumnWidth(twistlock, column=5, width=20) # packageName
    setColumnWidth(twistlock, column=6, width=20) # packageVersion
    setColumnWidth(twistlock, column=9, width=45) # vecStr
    setColumnWidth(twistlock, column=10, width=100) # justification

    anchore_cve = wb["Anchore CVE Results"]
    setColumnWidth(anchore_cve, column=2, width=25, wrap=False) # CVE
    setColumnWidth(anchore_cve, column=7, width=60) # url
    setColumnWidth(anchore_cve, column=8, width=100) # justification

    anchore_compliance = wb["Anchore Compliance Results"]
    setColumnWidth(anchore_compliance, column=11, width=30, wrap=False) # whitelist_name
    setColumnWidth(anchore_compliance, column=12, width=100, wrap=False) # justification
    setColumnWidth(anchore_compliance, column=6, width=75) # check_output


##### Main function
def main(argv, inheritableTriggerIds):
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

    # Apply Anchore compliance justifications
    print("Processing Anchore Compliance Results... ", end="", flush=True)
    justificationsAnchoreComp(wb, jAnchore, inheritableTriggerIds)
    print("done.")

    print("Formatting... ", end="", flush=True)
    setAllColumnWidths(wb)
    print("done.")



    # Save the Excel file
    wb.save(outputFile)


if __name__ == "__main__":
    main(sys.argv[1:], inheritableTriggerIds)
