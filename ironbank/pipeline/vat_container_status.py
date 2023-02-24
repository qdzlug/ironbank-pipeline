#!/usr/bin/env python3

from ironbank.pipeline.utils import logger

log = logger.setup(name="vat_container_status")


def log_unverified_findings(vat_response: dict) -> int:
    """
    Log unverified findings from vat response
    """
    vat_image = vat_response["image"]
    log.info(
        "VAT image %s:%s %s",
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

    if unverified_findings:
        log_findings(unverified_findings, "WARN")

    # return exit code
    return 0 if not unverified_findings else 100


def log_findings(findings: list, log_type: str) -> None:
    """
    Logs findings for the Check CVE stage of the pipeline
    """
    colors = {
        "bright_yellow": "\x1b[38;5;226m",
        "bright_red": "\x1b[38;5;196m",
        # RGB ANSI code
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


def log_findings_header(log_level: int) -> None:
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


def sort_justifications(vat_response) -> tuple[dict, dict, dict, dict]:
    """
    Findings are sorted into dictionary whose key is the scan source of the given finding

    Returns
        tuple of dictionaries, one for each scan source

        oscap, twistlock, anchore cve, anchore compliance
    """

    # use new scan source formats for vat report parsing
    sources: dict[str, dict] = {
        "Anchore CVE": {},
        "Anchore Compliance": {},
        "OSCAP Compliance": {},
        "Twistlock CVE": {},
    }

    for finding in vat_response["image"]["findings"]:
        if finding["state"]["findingStatus"].lower() in ("verified",):
            search_id = (
                finding["identifier"],
                finding.get("package", None),
                finding.get("packagePath", None),
            )
            sources[finding["scannerName"]][search_id] = (
                finding["justificationGate"]["justification"]
                if not finding["inheritsFrom"]
                else "Inherited from base image."
            )

    return (
        sources["Anchore CVE"],
        sources["Anchore Compliance"],
        sources["OSCAP Compliance"],
        sources["Twistlock CVE"],
    )
