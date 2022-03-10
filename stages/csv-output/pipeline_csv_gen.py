#!/usr/bin/env python3

import csv
import sys
import json
import os
import argparse
import pathlib
import logging
import xml.etree.ElementTree as etree

from scanners import anchore
from scanners.helper import write_csv_from_dict_list

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)

from vat_container_status import sort_justifications  # noqa E402


def main():
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

    parser = argparse.ArgumentParser(
        description="DCCSCR processing of CVE reports from various sources"
    )
    parser.add_argument("--twistlock", help="location of the twistlock JSON scan file")
    parser.add_argument("--oscap", help="location of the oscap scan XML file")
    parser.add_argument(
        "--anchore-sec", help="location of the anchore_security.json scan file"
    )
    parser.add_argument(
        "--anchore-gates", help="location of the anchore_gates.json scan file"
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        dest="output_dir",
        help="directory in which to write CSV output",
        default="./",
    )
    parser.add_argument("--sbom-dir", help="location of the anchore content directory")
    args = parser.parse_args()

    # Create the csv directory if not present
    pathlib.Path(args.output_dir).mkdir(parents=True, exist_ok=True)

    artifacts_path = os.environ["ARTIFACT_STORAGE"]
    # get cves and justifications from VAT
    vat_findings_file = pathlib.Path(artifacts_path, "vat", "vat_response.json")
    # load vat_findings.json file
    try:
        with vat_findings_file.open(mode="r") as f:
            vat_findings = json.load(f)
    except Exception:
        logging.exception("Error reading findings file.")
        sys.exit(1)

    logging.info("Gathering list of all justifications...")

    j_openscap, j_twistlock, j_anchore_cve, j_anchore_comp = sort_justifications(
        vat_findings
    )

    oscap_fail_count = 0
    twist_fail_count = 0
    anchore_num_cves = 0
    anchore_compliance = 0
    if args.oscap:
        oscap_fail_count = generate_oscap_report(
            args.oscap, j_openscap, csv_dir=args.output_dir
        )
    else:
        generate_blank_oscap_report(csv_dir=args.output_dir)
    if args.twistlock:
        twist_fail_count = generate_twistlock_report(
            args.twistlock, j_twistlock, csv_dir=args.output_dir
        )
    if args.anchore_sec:
        anchore_num_cves = anchore.vulnerability_report(
            csv_dir=args.output_dir,
            anchore_security_json=args.anchore_sec,
            justifications=j_anchore_cve,
        )
    if args.anchore_gates:
        anchore_compliance = anchore.compliance_report(
            csv_dir=args.output_dir,
            anchore_gates_json=args.anchore_gates,
            justifications=j_anchore_comp,
        )
    if args.sbom_dir:
        anchore.sbom_report(csv_dir=args.output_dir, sbom_dir=args.sbom_dir)

    generate_summary_report(
        csv_dir=args.output_dir,
        osc=oscap_fail_count,
        tlf=twist_fail_count,
        anchore_num_cves=anchore_num_cves,
        anchore_compliance=anchore_compliance,
    )


# def _get_complete_whitelist_for_image(vat_findings, status_list):
#     """
#     Pull all whitelisted CVEs for an image. Walk through the ancestry of a given
#     image and grab all of the approved vulnerabilities in VAT associated with w layer.

#     """
#     logging.info(
#         f"Generating whitelist for {os.environ['IMAGE_NAME']}:{os.environ['IMAGE_VERSION']}"
#     )
#     total_whitelist = []
#     # loop through each image, starting from child through each parent, grandparent, etc.
#     for image in vat_findings:
#         # loop through each finding
#         for finding in vat_findings[image]:
#             # if finding is approved
#             logging.debug(finding)
#             if finding["finding_status"].lower() in status_list:
#                 # if finding is uninheritable (i.e. Dockerfile findings), exclude from whitelist
#                 if (
#                     image != os.environ["IMAGE_NAME"]
#                     and finding["finding"] in _uninheritable_trigger_ids
#                 ):
#                     logging.debug(f"Excluding finding {finding['finding']} for {image}")
#                     continue
#                 # add finding as dictionary object in list
#                 # if finding is inherited, set justification as 'Inherited from base image.'
#                 total_whitelist.append(
#                     {
#                         "scan_source": finding["scan_source"],
#                         "cve_id": finding["finding"],
#                         "package": finding["package"],
#                         "package_path": finding["package_path"],
#                         "justification": finding["justification"]
#                         if image == os.environ["IMAGE_NAME"]
#                         else "Inherited from base image.",
#                     }
#                 )
#     logging.info(f"Found {len(total_whitelist)} total whitelisted CVEs")
#     return total_whitelist


# def _split_by_scan_source(total_whitelist):
#     """
#     Gather all justifications for any approved CVE for anchore, twistlock and openscap.
#     Keys are in the form (cve_id, package, package_name) for anchore_cve, (cve_id, package) for twistlock, or "cve_id" for anchore_comp and openscap.

#     Examples:
#         (CVE-2020-13434, sqlite-libs-3.26.0-11.el8, None) (anchore cve key)
#         (CVE-2020-8285, sqlite-libs-3.26.0-11.el8) (twistlock key, truncated)
#         CCE-82315-3 (openscap or anchore comp key)

#     """
#     cve_openscap = {}
#     cve_twistlock = {}
#     cve_anchore = {}
#     comp_anchore = {}

#     # Using results from VAT, loop all findings
#     # Loop through the findings and create the corresponding dict object based on the vuln_source
#     for finding in total_whitelist:
#         if "cve_id" in finding.keys():
#             # id used to search for justification when generating each scan's csv
#             search_id = (
#                 finding["cve_id"],
#                 finding["package"],
#                 finding["package_path"],
#             )
#             logging.debug(search_id)
#             if finding["scan_source"] == "oscap_comp":
#                 # only use cve_id
#                 cve_openscap[search_id[0]] = finding["justification"]
#             elif finding["scan_source"] == "twistlock_cve":
#                 # use cve_id and package
#                 cve_twistlock[search_id[0:2]] = finding["justification"]
#             elif finding["scan_source"] == "anchore_cve":
#                 # use full tuple
#                 cve_anchore[search_id] = finding["justification"]
#             elif finding["scan_source"] == "anchore_comp":
#                 # only use cve_id
#                 comp_anchore[search_id[0]] = finding["justification"]

#     return cve_openscap, cve_twistlock, cve_anchore, comp_anchore


# Blank OSCAP Report
def generate_blank_oscap_report(csv_dir):
    oscap_report = open(csv_dir + "oscap.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(oscap_report)
    csv_writer.writerow(
        ["OpenSCAP Scan Skipped Due to Base Image Used", "", "", "", "", "", "", "", ""]
    )
    oscap_report.close()


# SUMMARY REPORT
def generate_summary_report(csv_dir, osc, tlf, anchore_num_cves, anchore_compliance):
    sum_data = open(csv_dir + "summary.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(sum_data)

    header = ["Scan", "Automated Findings", "Manual Checks", "Total"]

    # if the osc arg type is an int, the scan was skipped so output zero values
    if type(osc) == int:
        osl = ["OpenSCAP - DISA Compliance", 0, 0, 0]
    # osc arg is a tuple, meaning the generate_oscap_report function was run
    else:
        osl = ["OpenSCAP - DISA Compliance", osc[0], osc[1], osc[0] + osc[1]]

    anchore_vulns = ["Anchore CVE Results", anchore_num_cves, 0, anchore_num_cves]
    anchore_comps = [
        "Anchore Compliance Results",
        anchore_compliance["stop_count"],
        0,
        anchore_compliance["stop_count"],
    ]
    twl = ["Twistlock Vulnerability Results", int(tlf or 0), 0, int(tlf or 0)]

    csv_writer.writerow(header)
    csv_writer.writerow(osl)
    csv_writer.writerow(twl)
    csv_writer.writerow(anchore_vulns)
    csv_writer.writerow(anchore_comps)
    csv_writer.writerow(
        [
            "Totals",
            osl[1] + anchore_vulns[1] + anchore_comps[1] + twl[1],
            osl[2] + anchore_vulns[2] + anchore_comps[2] + twl[2],
            osl[3] + anchore_vulns[3] + anchore_comps[3] + twl[3],
        ]
    )

    csv_writer.writerow("")
    # date_str = 'Scans performed on: ' + str(osc[2])
    # csv_writer.writerow(['Scans performed on:', ]) # need date scanned
    sha_str = f"Scans performed on container layer sha256: {anchore_compliance['image_id']},,,"
    csv_writer.writerow([sha_str])
    sum_data.close()


# Generate csv for OSCAP findings with justifications
def generate_oscap_report(oscap, justifications, csv_dir):
    oscap_cves = get_oscap_full(oscap, justifications)
    oscap_data = open(csv_dir + "oscap.csv", "w", encoding="utf-8")
    csv_writer = csv.writer(oscap_data)
    count = 0
    fail_count = 0
    nc_count = 0
    scanned = ""
    for line in oscap_cves:
        if count == 0:
            header = line.keys()
            csv_writer.writerow(header)
            count += 1
        if line["result"] == "fail":
            fail_count += 1
        elif line["result"] == "notchecked":
            nc_count += 1
        scanned = line["scanned_date"]
        try:
            csv_writer.writerow(line.values())
        except Exception as e:
            logging.error(f"problem writing line: {line.values()}")
            raise e
    oscap_data.close()
    return fail_count, nc_count, scanned


# Get full OSCAP report with justifications for csv export
def get_oscap_full(oscap_file, justifications):
    root = etree.parse(oscap_file)
    ns = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "xhtml": "http://www.w3.org/1999/xhtml",  # not actually needed
        "dc": "http://purl.org/dc/elements/1.1/",
    }
    patches_up_to_date_dupe = False
    cces = []
    for rule_result in root.findall("xccdf:TestResult/xccdf:rule-result", ns):
        # Current CSV values
        # title,ruleid,result,severity,identifiers,refs,desc,rationale,scanned_date,Justification
        rule_id = rule_result.attrib["idref"]
        severity = rule_result.attrib["severity"]
        date_scanned = rule_result.attrib["time"]
        result = rule_result.find("xccdf:result", ns).text
        logging.debug(f"{rule_id}")
        if result == "notselected":
            logging.debug(f"SKIPPING: 'notselected' rule {rule_id} ")
            continue

        if rule_id == "xccdf_org.ssgproject.content_rule_security_patches_up_to_date":
            if patches_up_to_date_dupe:
                logging.debug(
                    f"SKIPPING: rule {rule_id} - OVAL check repeats and this finding is checked elsewhere"
                )
                continue
            else:
                patches_up_to_date_dupe = True
        # Get the <rule> that corresponds to the <rule-result>
        # This technically allows xpath injection, but we trust XCCDF files from OpenScap enough
        rule = root.find(f".//xccdf:Rule[@id='{rule_id}']", ns)
        title = rule.find("xccdf:title", ns).text

        # UBI/ComplianceAsCode:
        identifiers = [ident.text for ident in rule.findall("xccdf:ident", ns)]
        if not identifiers:
            # Ubuntu/ComplianceAsCode
            identifiers = [rule_id]
        # We never expect to get more than one identifier
        assert len(identifiers) == 1
        logging.debug(f"{identifiers}")
        identifier = identifiers[0]
        # Revisit this if we ever switch UBI from ComplianceAsCode to DISA content

        def format_reference(ref):
            ref_title = ref.find("dc:title", ns)
            ref_identifier = ref.find("dc:identifier", ns)
            href = ref.attrib.get("href")
            if ref_title is not None:
                assert ref_identifier is not None
                return f"{ref_title.text}: {ref_identifier.text}"
            elif href:
                return f"{href} {ref.text}"

            return ref.text

        # This is now informational only, vat_import no longer uses this field
        references = "\n".join(
            format_reference(r) for r in rule.findall("xccdf:reference", ns)
        )
        assert references

        rationale_element = rule.find("xccdf:rationale", ns)
        # Ubuntu XCCDF has no <rationale>
        rationale = (
            etree.tostring(rationale_element, method="text").decode("utf-8").strip()
            if rationale_element is not None
            else ""
        )

        # Convert description to text, seems to work well:
        description = (
            etree.tostring(rule.find("xccdf:description", ns), method="text")
            .decode("utf8")
            .strip()
        )

        cve_justification = ""
        id = (identifier, None, None)
        if id in justifications:
            cve_justification = justifications[id]

        ret = {
            "title": title,
            "ruleid": rule_id,
            "result": result,
            "severity": severity,
            "identifiers": identifier,
            "refs": references,
            "desc": description,
            "rationale": rationale,
            "scanned_date": date_scanned,
            "Justification": cve_justification,
        }
        cces.append(ret)
    try:
        assert len(set(cce["identifiers"] for cce in cces)) == len(cces)
    except Exception as duplicate_idents:
        for cce in cces:
            print(cce["ruleid"], cce["identifiers"])
        raise duplicate_idents

    return cces


# Generate oval csv
# def generate_oval_report(oval, csv_dir):
#    oval_cves = get_oval_full(oval)
#    oval_data = open(csv_dir + "oval.csv", "w", encoding="utf-8")
#    csv_writer = csv.writer(oval_data)
#    count = 0
#    fail_count = 0
#    for line in oval_cves:
#        if count == 0:
#            header = line.keys()
#            csv_writer.writerow(header)
#            count += 1
#        if line["result"] == "true":
#            fail_count += 1
#        csv_writer.writerow(line.values())
#    oval_data.close()
#    return fail_count


# Get OVAL report for csv export
# def get_oval_full(oval_file):
# def get_packages(definition, root, ns):
#     criterions = definition.findall(".//d:criterion[@test_ref]", ns)
#     assert criterions
#     for criterion in criterions:
#         criterion_id = criterion.attrib['test_ref']
#         lin_test = root.findall(f".//lin-def:rpmverifyfile_test[@id='{criterion_id}']", ns)
#         lin_test += root.findall(f".//lin-def:dpkginfo_test[@id='{criterion_id}']", ns)
#         assert len(lin_test) == 1
#
#         object_ref = lin_test[0].find("lin-def:object", ns).attrib["object_ref"]
#
#         # This only matches <lin-def:rpminfo_object>, other objects like <lin-def:rpmverifyfile_object> aren't matched
#         lin_objects = root.findall(f".//lin-def:rpminfo_object[@id='{object_ref}']", ns)
#         lin_objects = root.findall(f".//lin-def:dpkginfo_object[@id='{object_ref}']", ns)
#         assert len(lin_objects) == 1
#         lin_object = lin_objects[0]
#
#         lin_name = lin_object.find("lin-def:name", ns)
#         if lin_name.text:
#             yield lin_name.text
#         else:
#             var_ref = lin_name.attrib["var_ref"]
#             constant_variable = root.find(f".//d:constant_variable[@id='{var_ref}']", ns)
#             values = constant_variable.findall('d:value', ns)
#             assert values
#             for value in values:
#                 yield value.text

# cves = []
# root = etree.parse(oval_file)
# tags = {elem.tag for elem in root.iter()}
# ns = {
#     "r": "http://oval.mitre.org/XMLSchema/oval-results-5",
#     "d": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
#     "lin-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux",
# }
# severity_dict = {
#     # UBI
#     "Critical": "critical",
#     "Important": "important",
#     "Moderate": "moderate",
#     "Low": "low",
#     "Unknown": "unknown",
#     # Ubuntu
#     # "Critical": "critical",
#     "High": "important",
#     "Medium": "moderate",
#     # "Low": "low",
#     "Negligible": "low",
#     "Untriaged": "unknown",
# }

# for e in root.findall("r:results/r:system/r:definitions/r:definition", ns):
#     definition_id = e.attrib["definition_id"]
#     result = e.attrib["result"]
#     logging.debug(definition_id)

#     definition = root.find(f".//d:definition[@id='{definition_id}']", ns)
#     if definition.attrib["class"] == "inventory":
#         # Skip "Check that Ubuntu 18.04 LTS (bionic) is installed." OVAL check
#         continue

#     description = definition.find("d:metadata/d:description", ns).text
#     title = definition.find("d:metadata/d:title", ns).text
#     severity = definition.find("d:metadata/d:advisory/d:severity", ns).text
#     severity = severity_dict[severity]
#     references = [
#         r.attrib.get("ref_id")
#         for r in definition.findall("d:metadata/d:reference", ns)
#     ]
#     assert references

#     # This is too slow. We're currently parsing the title for the package name in vat_import instead.
#     # packages = list(get_packages(definition, root, ns))
#     # assert packages

#     # ref is the identifier used by VAT, create one CSV line per ref:
#     for ref in references:
#         ret = {
#             "id": definition_id,
#             "result": result,
#             "cls": description,
#             "ref": ref,
#             "title": title,
#             # TODO: will adding columns break the XLSX generation?
#             "severity": severity,
#             # "packages": packages,
#         }
#         cves.append(ret)
# return cves


# Get results from Twistlock report for csv export
def generate_twistlock_report(twistlock_cve_json, justifications, csv_dir):
    with open(twistlock_cve_json, mode="r", encoding="utf-8") as f:
        json_data = json.load(f)
        cves = []
        if "vulnerabilities" in json_data["results"][0]:
            for d in json_data["results"][0]["vulnerabilities"]:
                # get associated justification if one exists
                cve_justification = ""
                # if d["description"]:
                id = (d["id"], f"{d['packageName']}-{d['packageVersion']}", None)
                # id = d["cve"] + "-" + d["description"]
                # else:
                #     id = d["cve"]
                if id in justifications.keys():
                    cve_justification = justifications[id]
                # else cve_justification is ""
                try:
                    cves.append(
                        {
                            "id": d["id"],
                            "cvss": d.get("cvss"),
                            "desc": d.get("description"),
                            "link": d.get("link"),
                            "packageName": d["packageName"],
                            "packageVersion": d["packageVersion"],
                            "severity": d["severity"],
                            "status": d.get("status"),
                            "vecStr": d.get("vector"),
                            "Justification": cve_justification,
                        }
                    )
                except KeyError as e:
                    logging.error(
                        "Missing key. Please contact the Iron Bank Pipeline and Ops (POPs) team"
                    )
                    logging.error(e.args)
                    sys.exit(1)
        else:
            cves = []

    fieldnames = [
        "id",
        "cvss",
        "desc",
        "link",
        "packageName",
        "packageVersion",
        "severity",
        "status",
        "vecStr",
        "Justification",
    ]

    write_csv_from_dict_list(
        dict_list=cves, fieldnames=fieldnames, filename="tl.csv", csv_dir=csv_dir
    )

    return len(cves)


if __name__ == "__main__":
    main()  # with if
