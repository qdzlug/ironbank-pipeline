#!/usr/bin/env python3

import logging
from dateutil import parser
from datetime import datetime, timezone

def is_approved(vat_resp_dict, check_ft_findings):
    logging.info(f"VAT image {vat_resp_dict['imageName']}:{vat_resp_dict['imageTag']} {vat_resp_dict['vatUrl']}")
    accredited = False
    not_expired = False
    ft_ineligible_findings = False
    # Check accredidation
    accredited = _is_accredited(vat_resp_dict)
    # Check earliest expiration
    not_expired = _check_expiration(vat_resp_dict)

    # Check CVEs - print unapproved findings on Check CVEs stage
    if check_ft_findings:
        ft_ineligible_findings = _check_findings(vat_resp_dict)

    return accredited and not_expired and not ft_ineligible_findings

def _is_accredited(vat_resp_dict):
    # Check accredidation
    if vat_resp_dict["accreditation"] in ("Conditionally Approved", "Approved"):
        return True

def _check_expiration(vat_resp_dict):
    # Check earliest expiration
    if "earliestExpiration" in vat_resp_dict:
        expiration_date = parser.parse(vat_resp_dict["earliestExpiration"])
        return datetime.now(timezone.utc) < expiration_date
    else:
        return False

def _check_findings(vat_resp_dict):
    ft_ineligible_findings = False
    for finding in vat_resp_dict["findings"]:
            if finding["findingState"] not in ("approved", "conditionally approved"):
                if not "fastTrackEligibility" in finding or not finding["fastTrackEligibility"]:
                    ft_ineligible_findings = True
                    logging.error(
                        f"{finding['identifier']:<20} {finding['source']:20} {finding.get('serverity', ''):20} {finding.get('package', ''):30} {finding.get('packagePath', '')}"
                    )
    return ft_ineligible_findings