#!/usr/bin/env python3

import argparse
import logging
import os
import pathlib
import sys

import openpyxl
from openpyxl.styles import Alignment, PatternFill, Font
from openpyxl.utils import get_column_letter
import pandas as pd


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

    parser = argparse.ArgumentParser(
        description="Gather csv directory path and name of justification spreadsheet"
    )
    parser.add_argument("-i", "--csv-dir", dest="csv", help="Directory for scan csvs")
    parser.add_argument(
        "-o", "--output-file", dest="output", help="Name for justification excel file"
    )
    args = parser.parse_args()

    # csv_dir is the directory of the scan csvs, output_file is final xlsx file with justifications and coloring
    csv_dir = args.csv
    output_file = args.output

    # Convert all csvs to excel sheets
    # Generates two .xlsx spreadsheets, one with justifications (output_file) and one without justifications (all_scans.xlsx)
    convert_to_excel(csv_dir, output_file)
    wb = openpyxl.load_workbook(output_file)
    # Colorize justifications for output_file
    _colorize_full(wb)
    _set_all_column_widths(wb)
    if os.environ["CI_COMMIT_BRANCH"] != "development" and os.environ["CI_COMMIT_BRANCH"] != "master":
        _add_sheet_banners(wb)
    wb.save(output_file)


def _add_sheet_banners(wb):
    for sheet in wb.sheetnames:
        ws = wb[sheet]
        ws.insert_rows(1)
        cell = ws.cell(row=1, column=1)
        cell.value = "THESE FINDINGS ARE UNOFFICIAL AS THEY HAVE BEEN GENERATED ON A BRANCH OTHER THAN DEVELOPMENT OR MASTER. ONLY JUSTIFICATIONS FOR DEVELOPMENT OR MASTER BRANCH FINDINGS ARE CONSIDERED OFFICIAL."
        cell.font = Font(name="Calibri", size=11, bold=True)
        cell.fill = PatternFill(
            start_color="00ff00ff", end_color="00ff00ff", fill_type="solid"
        )
        ws.merge_cells("A1:Z1")


def _colorize_full(wb):
    _colorize_anchore(wb)
    _colorize_anchore_comp(wb)
    _colorize_twistlock(wb)
    if not os.environ.get("DISTROLESS"):
        _colorize_openscap(wb)


def _get_column_index(sheet, value):
    justification_column = None
    for i, col in enumerate(sheet.columns):
        if col[0].value == value:
            justification_column = i + 1
            break

    if not justification_column:
        logging.error(f"Could not find '{value}' column")
        sys.exit(1)

    return justification_column


def _colorize_anchore(wb):
    """
    Colorize anchore cve justifications column

    """
    sheet = wb["Anchore CVE Results"]

    justification_column = _get_column_index(sheet=sheet, value="Justification")

    for r in range(1, sheet.max_row + 1):
        cell_justification = sheet.cell(row=r, column=justification_column)
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


def _colorize_anchore_comp(wb):
    # colorize anchore comp justifications column
    sheet = wb["Anchore Compliance Results"]

    justification_column = _get_column_index(sheet=sheet, value="Justification")

    for r in range(1, sheet.max_row + 1):
        cell_justification = sheet.cell(row=r, column=justification_column)
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


def _colorize_twistlock(wb):
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


def _colorize_openscap(wb):
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


def _write_sbom_to_excel(csv_dir, writer):
    for report in os.listdir(f"{csv_dir}/sbom"):
        read_report = pd.read_csv(pathlib.Path(csv_dir, "sbom", report))
        read_report.to_excel(
            writer,
            sheet_name=f"SBOM {report.split('.')[0]}",
            header=True,
            index=False,
        )


# convert all csvs to Excel file
# Generates output_file (w/ justifications) and all_scans.xlsx (w/o justifications)
def convert_to_excel(csv_dir, justification_sheet):
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
        _write_sbom_to_excel(csv_dir=csv_dir, writer=writer)
    writer.save()
    with pd.ExcelWriter(
        justification_sheet
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
        _write_sbom_to_excel(csv_dir=csv_dir, writer=writer)
    writer.save()


def _set_column_width(sheet, column_value, width, wrap=False):
    """
    Set column width and enable text wrap

    """
    column = _get_column_index(sheet=sheet, value=column_value)
    sheet.column_dimensions[get_column_letter(column)].width = width
    if wrap:
        for cell in sheet[get_column_letter(column)]:
            cell.alignment = Alignment(wrap_text=True)


def _set_all_column_widths(wb):
    if not os.environ.get("DISTROLESS"):
        openscap_disa = wb["OpenSCAP - DISA Compliance"]
        _set_column_width(
            openscap_disa, column_value="scanned_date", width=20
        )  # scanned_date
        _set_column_width(
            openscap_disa, column_value="Justification", width=30
        )  # justification

    twistlock = wb["Twistlock Vulnerability Results"]
    _set_column_width(twistlock, column_value="id", width=25)  # CVE
    _set_column_width(twistlock, column_value="packageName", width=20)  # packageName
    _set_column_width(
        twistlock, column_value="packageVersion", width=20
    )  # packageVersion
    _set_column_width(twistlock, column_value="vecStr", width=45)  # vecStr
    _set_column_width(
        twistlock, column_value="Justification", width=100
    )  # justification

    anchore_cve = wb["Anchore CVE Results"]
    _set_column_width(anchore_cve, column_value="cve", width=25)  # CVE
    _set_column_width(anchore_cve, column_value="url", width=60)  # url
    _set_column_width(
        anchore_cve, column_value="Justification", width=100
    )  # justification

    anchore_compliance = wb["Anchore Compliance Results"]
    _set_column_width(
        anchore_compliance, column_value="whitelist_name", width=30
    )  # whitelist_name
    _set_column_width(
        anchore_compliance, column_value="check_output", width=75
    )  # check_output
    _set_column_width(
        anchore_compliance, column_value="Justification", width=100
    )  # justification


if __name__ == "__main__":
    main(sys.argv[1:])
