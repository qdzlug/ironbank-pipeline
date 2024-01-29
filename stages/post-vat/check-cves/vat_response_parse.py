#!/usr/bin/env python3

import json
import os
import sys
from pathlib import Path
import logging


def setup(name="main", level=None, log_format=None, debug_file=None):
    """Set up a logger with the given parameters. Use environment variables or
    defaults if parameters are not provided.

    Args:
        name (str, optional): The name of the logger. Defaults to "main".
        level (str, optional): The level of logging. Defaults to environment
            variable "LOGLEVEL" if set, otherwise to "INFO".
        log_format (str, optional): The format of the logging messages. If not
            provided, a default format will be used based on the level.
        debug_file (str, optional): A file to which debug level logs should be
            written. If not provided, debug logs are not written to a file.

    Returns:
        Logger: A configured logger.
    """
    level = level if level else os.environ.get("LOGLEVEL", "INFO").upper()
    default_format = (
        "| %(levelname)s | [%(filename)s: %(lineno)d]: | %(message)s"
        if level == "DEBUG"
        else "| %(name)-28s | %(levelname)-8s | %(message)s"
    )

    log_format = log_format or default_format
    logging.basicConfig(level=level, stream=sys.stdout, format=log_format)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if debug_file:
        formatter = logging.Formatter(log_format)
        file_handler = logging.FileHandler(debug_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger


log = setup("vat_container_status")


def log_findings_header(log_level: int) -> None:
    """Logs a header line for the findings at the specified log level.

    Args:
        log_level (int): The logging level at which to log the header.
    """
    values = {
        "identifier": "Identifier",
        "scannerName": "Scanner Name",
        "severity": "Severity",
        "package": "Package",
        "packagePath": "Package Path",
        "inheritsFrom": "Inherits From",
    }
    log.log(
        log_level,
        f"{values['identifier']:<20} {values['scannerName']:20} {values.get('severity', ''):20} {values.get('package', ''):35} {values.get('packagePath', ''):45} {values['inheritsFrom']}",
    )


def log_findings(findings: list, log_type: str) -> None:
    """Logs findings for the Check CVE stage of the pipeline.

    Args:
        findings (list): A list of findings to log.
        log_type (str): The type of log message, such as "WARN" or "ERR".
    """
    colors = {
        "bright_yellow": "\x1b[38;5;226m",
        "bright_red": "\x1b[38;5;196m",
        "white": "\x1b[38;2;255;255;255m",
    }
    finding_color: str
    log_level: int
    if log_type == "WARN":
        finding_color = colors["bright_yellow"]
        log_level = 30
        log.debug("Fast Track eligible findings")
    elif log_type == "ERR":
        finding_color = colors["bright_red"]
        log_level = 40
        log.debug("Fast Track ineligible findings")
    log_findings_header(log_level)
    for finding in findings:
        log.log(
            log_level,
            f"{finding_color}{finding['identifier']:<20} {finding['scannerName']:20} {finding.get('severity', ''):20} {finding.get('package', ''):35} {finding.get('packagePath', ''):45} {colors['white']}{finding['inheritsFrom'] if finding['inheritsFrom'] else 'Uninherited'}",
        )


def log_unverified_findings(vat_response: dict) -> int:
    """Log unverified findings from the VAT response.

    Args:
        vat_response (dict): The VAT response containing findings.

    Returns:
        int: An exit code indicating the result of the logging operation.
    """
    vat_image = vat_response["image"]
    log.info(
        "VAT image %s:%s %s ",
        vat_image["imageName"],
        vat_image["tag"],
        vat_image["vatUrl"],
    )

    findings: list[dict] = vat_image["findings"]

    unverified_findings = [
        finding
        for finding in findings
        if finding["state"]["findingStatus"] != "Verified"
    ]

    log_findings(unverified_findings, "WARN")
    return 0 if not unverified_findings else 100


def main() -> None:
    """Main function to process and log findings from the VAT response."""
    vat_response: dict = json.loads(
        Path(f"{os.environ['ARTIFACT_STORAGE']}/vat/vat_response.json").read_text(
            encoding="utf-8"
        )
    )
    exit_code = log_unverified_findings(vat_response)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
