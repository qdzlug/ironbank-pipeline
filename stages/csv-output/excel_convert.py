#!/usr/bin/env python3
import openpyxl
from openpyxl.styles import Alignment, PatternFill
from openpyxl.utils import get_column_letter

import pandas as pd
import logging
import sys
import argparse
import os


def main(argv):
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

    # Process command-line arguments
    csv_dir = ""
    output_file = ""

    parser = argparse.ArgumentParser(description="Gather csv directory path and name of justification spreadsheet")
    parser.add_argument("-i", "--csv-dir", dest="csv", help="Directory for scan csvs")
    parser.add_argument("-o", "--output-file", dest="output", help="Name for justification excel file")
    args = parser.parse_args()

    # csv_dir is the directory of the scan csvs, output_file is final xlsx file with justifications and coloring
    csv_dir = args.csv
    output_file = args.output

    # Convert all csvs to excel sheets
    # Generates two .xlsx spreadsheets, one with justifications (output_file) and one without justifications (all_scans.xlsx)
    convert_to_excel(csv_dir, output_file)
    wb = openpyxl.load_workbook(output_file)
    # Colorize justifications for output_file
    colorize_full(wb)
    setAllColumnWidths(wb)
    wb.save(output_file)


def colorize_full(wb):
    colorize_anchore(wb)
    colorize_anchore_comp(wb)
    colorize_twistlock(wb)
    colorize_openscap(wb)


def colorize_anchore(wb):
    # colorize anchore justifications column
    sheet = wb["Anchore CVE Results"]
    for r in range(1, sheet.max_row + 1):
        cell = sheet.cell(row=r, column=2)
        if cell.value == "cve":
            cell = sheet.cell(row=r, column=9)
            cell.value = "Justification"
        else:
            cell_justification = sheet.cell(row=r, column=9)
            # Apply appropriate highlighting to justification cell
            if cell_justification.value is None:
                cell_justification.fill = PatternFill(
                    start_color="00ffff00", end_color="00ffff00", fill_type="solid"
                )
            elif cell_justification.value == "Inherited from base image.":
                cell_justification.fill = PatternFill(
                    start_color="0000b050", end_color="0000b050", fill_type="solid"
                )
            else:
                cell_justification.fill = PatternFill(
                    start_color="0000b0f0", end_color="0000b0f0", fill_type="solid"
                )


def colorize_anchore_comp(wb):
    # colorize anchore comp justifications column
    sheet = wb["Anchore Compliance Results"]
    for r in range(1, sheet.max_row + 1):
        cell = sheet.cell(row=r, column=3)
        if cell.value == "trigger_id":
            cell = sheet.cell(row=r, column=13)
            cell.value = "Justification"
        else:
            cell_justification = sheet.cell(row=r, column=13)
            # Apply appropriate highlighting to justification cell
            if cell_justification.value is None:
                cell_justification.fill = PatternFill(
                    start_color="00ffff00", end_color="00ffff00", fill_type="solid"
                )
            elif cell_justification.value == "Inherited from base image.":
                cell_justification.fill = PatternFill(
                    start_color="0000b050", end_color="0000b050", fill_type="solid"
                )
            elif cell_justification.value == "See Anchore CVE Results sheet":
                cell_justification.fill = PatternFill(
                    start_color="96969696", end_color="96969696", fill_type="solid"
                )
            else:
                cell_justification.fill = PatternFill(
                    start_color="0000b0f0", end_color="0000b0f0", fill_type="solid"
                )


def colorize_twistlock(wb):
    # colorize twistlock justifications column
    sheet = wb["Twistlock Vulnerability Results"]
    for r in range(1, sheet.max_row + 1):
        cell = sheet.cell(row=r, column=1)
        if cell.value == "id":
            cell = sheet.cell(row=r, column=10)
            cell.value = "Justification"
        else:
            cell_justification = sheet.cell(row=r, column=10)
            # Apply appropriate highlighting to justification cell
            if cell_justification.value is None:
                cell_justification.fill = PatternFill(
                    start_color="00ffff00", end_color="00ffff00", fill_type="solid"
                )
            elif cell_justification.value == "Inherited from base image.":
                cell_justification.fill = PatternFill(
                    start_color="0000b050", end_color="0000b050", fill_type="solid"
                )
            else:
                cell_justification.fill = PatternFill(
                    start_color="0000b0f0", end_color="0000b0f0", fill_type="solid"
                )


def colorize_openscap(wb):
    # colorize oscap justifications column
    sheet = wb["OpenSCAP - DISA Compliance"]
    for r in range(1, sheet.max_row + 1):
        cell = sheet.cell(row=r, column=5)
        if cell.value == "identifiers":
            cell = sheet.cell(row=r, column=10)
            cell.value = "Justification"
        else:
            cell_justification = sheet.cell(row=r, column=10)
            # Apply appropriate highlighting to justification cell
            if cell_justification.value is None:
                cell_justification.fill = PatternFill(fill_type=None)
            elif cell_justification.value == "Inherited from base image.":
                cell_justification.fill = PatternFill(
                    start_color="0000b050", end_color="0000b050", fill_type="solid"
                )
            else:
                cell_justification.fill = PatternFill(
                    start_color="0000b0f0", end_color="0000b0f0", fill_type="solid"
                )


# convert all csvs to Excel file
# Generates output_file (w/ justifications) and all_scans.xlsx (w/o justifications)
def convert_to_excel(csv_dir, justificationSheet):
    read_sum = pd.read_csv(csv_dir + "summary.csv")
    read_oscap = pd.read_csv(csv_dir + "oscap.csv")
    read_oval = pd.read_csv(csv_dir + "oval.csv")
    read_tl = pd.read_csv(csv_dir + "tl.csv")
    read_security = pd.read_csv(csv_dir + "anchore_security.csv")
    read_gates = pd.read_csv(csv_dir + "anchore_gates.csv")
    # column slice, remove last column which is justification to keep all_scans.xlsx with normal format
    read_oscap_no_justifications = read_oscap.iloc[:, :-1]
    read_tl_no_justifications = read_tl.iloc[:, :-1]
    read_security_no_justifications = read_security.iloc[:, :-1]
    read_gates_no_justifications = read_gates.iloc[:, :-1]
    # create all_scan.xlsx file (no justification or coloring used)
    with pd.ExcelWriter(
        csv_dir + "all_scans.xlsx"
    ) as writer:  # pylint: disable=abstract-class-instantiated
        read_sum.to_excel(writer, sheet_name="Summary", header=True, index=False)
        read_oscap_no_justifications.to_excel(
            writer, sheet_name="OpenSCAP - DISA Compliance", header=True, index=False
        )
        read_oval.to_excel(
            writer, sheet_name="OpenSCAP - OVAL Results", header=True, index=False
        )
        read_tl_no_justifications.to_excel(
            writer,
            sheet_name="Twistlock Vulnerability Results",
            header=True,
            index=False,
        )
        read_security_no_justifications.to_excel(
            writer, sheet_name="Anchore CVE Results", header=True, index=False
        )
        read_gates_no_justifications.to_excel(
            writer, sheet_name="Anchore Compliance Results", header=True, index=False
        )
    writer.save()
    with pd.ExcelWriter(
        justificationSheet
    ) as writer:  # pylint: disable=abstract-class-instantiated
        read_sum.to_excel(writer, sheet_name="Summary", header=True, index=False)
        read_oscap.to_excel(
            writer, sheet_name="OpenSCAP - DISA Compliance", header=True, index=False
        )
        read_oval.to_excel(
            writer, sheet_name="OpenSCAP - OVAL Results", header=True, index=False
        )
        read_tl.to_excel(
            writer,
            sheet_name="Twistlock Vulnerability Results",
            header=True,
            index=False,
        )
        read_security.to_excel(
            writer, sheet_name="Anchore CVE Results", header=True, index=False
        )
        read_gates.to_excel(
            writer, sheet_name="Anchore Compliance Results", header=True, index=False
        )
    writer.save()


def setColumnWidth(sheet, column, width, wrap=False):
    """Set column width and enable text wrap"""
    sheet.column_dimensions[get_column_letter(column)].width = width
    if wrap:
        for cell in sheet[get_column_letter(column)]:
            cell.alignment = Alignment(wrap_text=True)


def setAllColumnWidths(wb):
    openscap_disa = wb["OpenSCAP - DISA Compliance"]
    setColumnWidth(openscap_disa, column=9, width=20)  # scanned_date
    setColumnWidth(openscap_disa, column=10, width=30)  # justification

    twistlock = wb["Twistlock Vulnerability Results"]
    setColumnWidth(twistlock, column=1, width=25)  # CVE
    setColumnWidth(twistlock, column=5, width=20)  # packageName
    setColumnWidth(twistlock, column=6, width=20)  # packageVersion
    setColumnWidth(twistlock, column=9, width=45)  # vecStr
    setColumnWidth(twistlock, column=10, width=100)  # justification

    anchore_cve = wb["Anchore CVE Results"]
    setColumnWidth(anchore_cve, column=2, width=25, wrap=False)  # CVE
    setColumnWidth(anchore_cve, column=7, width=60)  # url
    setColumnWidth(anchore_cve, column=9, width=100)  # justification

    anchore_compliance = wb["Anchore Compliance Results"]
    setColumnWidth(
        anchore_compliance, column=12, width=30, wrap=False
    )  # whitelist_name
    setColumnWidth(
        anchore_compliance, column=13, width=100, wrap=False
    )  # justification
    setColumnWidth(anchore_compliance, column=6, width=75)  # check_output


if __name__ == "__main__":
    main(sys.argv[1:])
