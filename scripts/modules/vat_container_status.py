#!/usr/bin/env python3

import logging
from dateutil import parser
from datetime import datetime, timezone


def is_approved(vat_resp_dict, check_ft_findings):
    accredited = False
    not_expired = False
    ft_ineligible_findings = False
    approval_status = "notapproved"
    approval_comment = None
    # Check accreditation
    if vat_resp_dict:
        logging.info(
            f"VAT image {vat_resp_dict['imageName']}:{vat_resp_dict['imageTag']} {vat_resp_dict['vatUrl']}"
        )
        accredited = _is_accredited(vat_resp_dict)
        approval_comment = vat_resp_dict["accreditationComment"]
        approval_status = vat_resp_dict["accreditation"]
        # Check earliest expiration
        not_expired = _check_expiration(vat_resp_dict)

        # Check CVEs - print unapproved findings on Check CVEs stage
        if check_ft_findings:
            ft_ineligible_findings = _check_findings(vat_resp_dict)

    return (
        accredited and not_expired and not ft_ineligible_findings,
        approval_status,
        approval_comment,
    )


def _is_accredited(vat_resp_dict):
    # Check accreditation
    if vat_resp_dict["accreditation"] in ("Conditionally Approved", "Approved"):
        return True


def _check_expiration(vat_resp_dict):
    # Check earliest expiration
    if "earliestExpiration" in vat_resp_dict:
        expiration_date = parser.parse(vat_resp_dict["earliestExpiration"])
        return datetime.now(timezone.utc) < expiration_date
    else:
        return True


def _check_findings(vat_resp_dict):
    ft_ineligible_findings = False
    for finding in vat_resp_dict["findings"]:
        if finding["findingsState"] not in ("approved", "conditionally approved"):
            if (
                not "fastTrackEligibility" in finding
                or not finding["fastTrackEligibility"]
            ):
                ft_ineligible_findings = True
                logging.error(
                    f"{finding['identifier']:<20} {finding['source']:20} {finding.get('serverity', ''):20} {finding.get('package', ''):30} {finding.get('packagePath', '')}"
                )
    return ft_ineligible_findings


def sort_justifications(vat_resp_dict):

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
