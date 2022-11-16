#!/usr/bin/env python3

import logging
import os
from pathlib import Path
import xml.etree.ElementTree as etree
import requests
import re
import bz2
import sys


def _format_reference(ref, n_set):
    ref_title = ref.find("dc:title", n_set)
    ref_identifier = ref.find("dc:identifier", n_set)
    if ref_title is not None:
        assert ref_identifier is not None
        return f"{ref_title.text}: {ref_identifier.text}"
    return ref.text


# Get full OSCAP report with justifications for csv export
def generate_oscap_jobs(oscap_path):
    oc_path = Path(oscap_path)

    root = etree.parse(oc_path)
    n_set = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "xhtml": "http://www.w3.org/1999/xhtml",  # not actually needed
        "dc": "http://purl.org/dc/elements/1.1/",
    }

    cces = []
    for rule_result in root.findall("xccdf:TestResult/xccdf:rule-result", n_set):
        rule_id = rule_result.attrib["idref"]
        severity = rule_result.attrib["severity"]
        result = rule_result.find("xccdf:result", n_set).text
        logging.debug(f"Rule ID: {rule_id}")
        if result in ["notchecked", "fail", "error"]:
            if (
                rule_id
                == "xccdf_org.ssgproject.content_rule_security_patches_up_to_date"
            ):
                check_content_ref_name = rule_result.find(
                    "xccdf:check/xccdf:check-content-ref", n_set
                ).attrib["name"]
                check_content_ref_href = rule_result.find(
                    "xccdf:check/xccdf:check-content-ref", n_set
                ).attrib["href"]
                oval_cves = get_oval_findings(
                    check_content_ref_name, check_content_ref_href, severity.lower()
                )
                cces += oval_cves
            else:
                # Get the <rule> that corresponds to the <rule-result>
                # This technically allows xpath injection, but we trust XCCDF files from OpenScap enough
                rule = root.find(f".//xccdf:Rule[@id='{rule_id}']", n_set)
                # UBI/ComplianceAsCode:
                identifiers = [
                    ident.text for ident in rule.findall("xccdf:ident", n_set)
                ]
                if not identifiers:
                    # Ubuntu/ComplianceAsCode
                    identifiers = [rule_id]
                # We never expect to get more than one identifier
                assert len(identifiers) == 1
                logging.debug(f"Identifiers {identifiers}")
                identifier = identifiers[0]

                # This is now informational only, vat_import no longer uses this field
                references = "\n".join(
                    _format_reference(r_l, n_set)
                    for r_l in rule.findall("xccdf:reference", n_set)
                )
                assert references

                # Convert description to text
                description = (
                    etree.tostring(rule.find("xccdf:description", n_set), method="text")
                    .decode("utf8")
                    .strip()
                )

                ret = {
                    "finding": identifier,
                    "severity": severity.lower(),
                    "description": description,
                    "link": None,
                    "score": "",
                    "package": None,
                    "packagePath": None,
                    # use old format for scan report parsing
                    "scanSource": "oscap_comp",
                }
                cces.append(ret)
        if result == "notselected":
            logging.debug(f"SKIPPING: 'notselected' rule {rule_id}")
    try:
        assert len(set(cce["finding"] for cce in cces)) == len(cces)
    except Exception as duplicate_idents:
        for cce in cces:
            logging.info(f"Duplicate: {cce['finding']}")
        raise duplicate_idents

    return cces


def get_oval_findings(finding_name, finding_href, severity):
    if "RHEL9" in finding_href:
        version = 9
    elif "RHEL8" in finding_href:
        version = 8
    elif "RHEL7" in finding_href:
        version = 7
    else:
        logging.error("OVAL findings found for non-ubi based image")
        sys.exit(1)

    url = f"https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL{version}.xml.bz2"
    root = get_redhat_oval_definitions(url)

    n_set = {
        "oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
    }
    oval_cves = []
    definition = root.find(f".//oval:definition[@id='{finding_name}']", n_set)
    description = definition.find("oval:metadata/oval:title", n_set).text
    for cve in definition.findall("oval:metadata/oval:advisory/oval:cve", n_set):
        link = cve.attrib["href"]
        identifier = cve.text
        cve_dict = {
            "finding": identifier,
            "link": link,
            "description": description,
            "severity": severity,
            "score": "",
            "package": None,
            "packagePath": None,
            # use old format for scan report parsing
            "scanSource": "oscap_comp",
        }
        oval_cves.append(cve_dict)
    return oval_cves


def get_redhat_oval_definitions(url):
    oval_definitions = {}
    if url in oval_definitions:
        return oval_definitions[url]
    r = requests.get(url)
    artifact_path = f"{os.environ['ARTIFACT_DIR']}/oval_definitions-{re.sub(r'[^a-z]', '-', url)}.xml"
    open(artifact_path, "wb").write(r.content)
    data = bz2.BZ2File(artifact_path).read()
    data_string = str(data, "utf-8")
    open(artifact_path, "w").write(data_string)
    oval_definitions[url] = etree.parse(artifact_path)
    return oval_definitions[url]
