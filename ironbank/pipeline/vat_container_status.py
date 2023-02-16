#!/usr/bin/env python3

from ironbank.pipeline.utils import logger

log = logger.setup(name="vat_container_status")


def is_approved(vat_resp_dict, findings) -> int:
    """
    FIX ME
    """
    vat_image = vat_resp_dict["image"]

    exists_in_vat = bool(vat_image)

    if exists_in_vat:
        log.info(
            f"VAT image {vat_image['imageName']}:{vat_image['tag']} {vat_image['vatUrl']}"
        )

    statuses: dict[str, list[str]] = {
        # nothing for the maintainers/fa to do
        "no_issues": ["Verified"],
        # something for the maintainer to update
        "maintainer_warnings": ["Needs Justification", "Needs Rework"],
        # something for the finding approver to update
        "finding_approver_warnings": ["Justified", "Needs Reverification"],
    }

    findings_by_status: dict[str, list[dict]] = {}
    for finding in findings:
        status = finding["state"]["findingStatus"]
        findings_by_status[status] = (
            [*findings_by_status[status], finding]
            if findings_by_status.get(status)
            else [finding]
        )

    # Exit codes for Check CVE parsing of VAT response
    # 0   - fix me
    # 100 - fix me
    # 100 - fix me
    exit_code: int = 0

    # check for existence of finding status type in response
    # key will not be exist if not applicable to at least one finding
    status_type_found = lambda status: bool(  # noqa E731
        [k for k in findings_by_status.keys() if k in statuses[status]]
    )
    maintainer_actions_required = status_type_found("maintainer_warnings")
    # fa_actions_required = status_type_found("finding_approver_warnings")

    if maintainer_actions_required:
        # TODO: uncomment this after confirming it won't cause issues for robotnik
        # log.info("Maintainer actions required on the following findings")
        for status in statuses["maintainer_warnings"]:
            log_findings(findings_by_status[status], "WARN")
        exit_code = 100
    # if fa_actions_required:
    #     log.info("Finding approver actions required on the following findings")
    #     for status in statuses["maintainer_warnings"]:
    #         log_findings(findings_by_status[status], "WARN")
    #     exit_code = 100

    return exit_code


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


def sort_justifications(vat_resp_dict) -> tuple[dict, dict, dict, dict]:
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

    for finding in vat_resp_dict["image"]["findings"]:
        if finding["state"]["findingStatus"].lower() in (
            "approved",
            "conditionally approved",
        ):
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
