#!/usr/bin/env python3

import logging
import os
from dateutil import parser
from datetime import datetime, timezone


def is_approved(vat_resp_dict, check_ft_findings) -> tuple[int, str, str]:
    accredited = False
    not_expired = False
    ft_eligible_findings = False
    ft_ineligible_findings = False
    approval_status = "notapproved"
    approval_comment = None
    # Check accreditation
    if vat_resp_dict:
        logging.info(
            f"VAT image {vat_resp_dict['imageName']}:{vat_resp_dict['imageTag']} {vat_resp_dict['vatUrl']}"
        )
        accredited = _is_accredited(vat_resp_dict)
        if "accreditationComment" in vat_resp_dict:
            approval_comment = vat_resp_dict["accreditationComment"]
        approval_status = vat_resp_dict["accreditation"]
        # Check earliest expiration
        not_expired = _check_expiration(vat_resp_dict)

        # Check CVEs - print unapproved findings on Check CVEs stage
        if check_ft_findings:
            # _log_ft_eligible_findings(vat_resp_dict)
            ft_eligible_findings, ft_ineligible_findings = _check_findings(
                vat_resp_dict
            )
    # Exit codes for Check CVE parsing of VAT response
    # 0   - Container is accredited, accreditation is not expired, and there are no unapproved findings
    # 1   - Either Container is not accredited, or the accreditation has expired, or there is an unapproved finding not eligible to be fast tracked
    # 100 - Container is accredited, accreditation is not expired, and there are unapproved findings but they are ALL eligible to be fast tracked. This exit code is permitted to fail the Check CVE job
    exit_code: int
    # The first case should be a hard fail, as either the container is not accredited, the accreditation is expired, or there are unapproved findings that cannot be fast tracked
    if not accredited or not not_expired or ft_ineligible_findings:
        if os.environ["CI_COMMIT_BRANCH"] == "master":
            exit_code = 1
        else:
            exit_code = 100
    elif ft_eligible_findings:
        exit_code = 100
    else:
        exit_code = 0

    return (
        exit_code,
        approval_status,
        approval_comment,
    )


def _is_accredited(vat_resp_dict) -> bool:
    """
    Checks if a container's 'accreditation' is Conditionally Approved, or Approved

    Returns
        boolean:
        True indicates accredited.
        False indicates not accredited.
    """
    # Check accreditation
    if vat_resp_dict["accreditation"] in ("Conditionally Approved", "Approved"):
        return True


def _check_expiration(vat_resp_dict) -> bool:
    """
    Checks if a container's 'earliestExpiration'. If key is present, check if current date is previous to expiration date. If 'earliestExpiration' key is not found, return True

    Returns
        boolean:
        True indicates container's accreditation is not expired.
        False indicates container's accreditation has expired
    """
    # Check earliest expiration
    if "earliestExpiration" in vat_resp_dict:
        expiration_date = parser.parse(vat_resp_dict["earliestExpiration"])
        return datetime.now(timezone.utc) < expiration_date
    else:
        return True


def _check_findings(vat_resp_dict) -> tuple[bool, bool]:
    """
    Pulls all non-approved findings into a list
    Then separates these into two lists of fast-track (ft) eligible and ft-ineligible findings
    Logs the lists out and returns booleans indicating if either ft or non-ft findings, that are not approved, exist
    Returns tuple of booleans, Fast track eligible, and fast track ineligible. False indicates not found while True means at lease one finding is present
    """
    ft_eligible = False
    ft_ineligible = False
    ft_eligible_findings = []
    ft_ineligible_findings = []
    findings: list[dict] = vat_resp_dict["findings"]
    # pull out findings that are not approved into a list to be used for finding ft eligible and ft ineligible findings
    for unapproved in (
        finding
        for finding in findings
        if finding["findingsState"] not in ("approved", "conditional")
    ):
        # if a finding can be fast tracked, the key of fastTrackEligibility will exist in the finding
        # also confirm that list of ft codes is not empty. This should never be the case and this check may be able to be removed in the future.
        # //TODO Review with VAT team if ONLY checking for "fastTrackEligibility" key is sufficient for this logic check
        if "fastTrackEligibility" in unapproved and unapproved["fastTrackEligibility"]:
            ft_eligible_findings.append(unapproved)
        else:
            ft_ineligible_findings.append(unapproved)
    #  if ft_eligible_findings is not an empty list, log findings and set boolean to True
    if ft_eligible_findings:
        log_finding(ft_eligible_findings, "WARN")
        ft_eligible = True
    #  if ft_ineligible_findings is not an empty list, log findings and set boolean to True
    if ft_ineligible_findings:
        log_finding(ft_ineligible_findings, "ERR")
        ft_ineligible = True
    return ft_eligible, ft_ineligible


def log_finding(findings: list, log_type: str):
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
        logging.debug("Fast Track eligible findings")
    elif log_type == "ERR":
        finding_color = colors["bright_red"]
        log_level = 40
        logging.debug("Fast Track ineligible findings")
    log_findings_header(log_level)
    for finding in findings:
        logging.log(
            log_level,
            f"{finding_color}{finding['identifier']:<20} {finding['source']:20} {finding.get('severity', ''):20} {finding.get('package', ''):35} {finding.get('packagePath', '')}{colors['white']}",
        )


def log_findings_header(log_level: int) -> None:
    values = {
        "identifier": "Identifier",
        "source": "Source",
        "severity": "Severity",
        "package": "Package",
        "packagePath": "Package Path",
    }
    logging.log(
        log_level,
        f"{values['identifier']:<20} {values['source']:20} {values.get('severity', ''):20} {values.get('package', ''):35} {values.get('packagePath', '')}",
    )
    return


def sort_justifications(vat_resp_dict) -> tuple[dict, dict, dict, dict]:
    """
    Findings are sorted into dictionary who's key is the scan source of the given finding

    Returns
        tuple of dictionaries, one for each scan source

        oscap, twistlock, anchore cve, anchore compliance
    """
    sources = {
        "anchore_cve": {},
        "anchore_comp": {},
        "oscap_comp": {},
        "twistlock_cve": {},
    }

    for finding in vat_resp_dict["findings"]:
        if finding["findingsState"] in ("approved", "conditionally approved"):
            search_id = (
                finding["identifier"],
                finding["package"] if "package" in finding else None,
                finding["packagePath"] if "packagePath" in finding else None,
            )
            sources[finding["source"]][search_id] = finding["contributor"][
                "justification"
            ]

    return (
        sources["oscap_comp"],
        sources["twistlock_cve"],
        sources["anchore_cve"],
        sources["anchore_comp"],
    )
