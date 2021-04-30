import re
import logging
import xml.etree.ElementTree as etree

# Keeping the code around for future use, but OVAL scans have been deprecated in P1
#def get_oval(oval_file):
#    cves = list()
#    with oval_file.open(mode="r", encoding="utf-8") as of:
#        soup = BeautifulSoup(of, "html.parser")
#        results_bad = soup.find_all("tr", class_=["resultbadA", "resultbadB"])
#
#        for x in results_bad:
#            id = x.find("td")
#            result = id.find_next_sibling("td")
#            cls = result.find_next_sibling("td")
#            title = cls.find_next_sibling("td").find_next_sibling("td")
#            y = x.find_all(target="_blank")
#            references = set()
#            for t in y:
#                references.add(t.text)
#
#            for ref in references:
#                pkgs = get_packages(title.text)
#                ret = {
#                    "id": id.text,
#                    "result": result.text,
#                    "cls": cls.text,
#                    "ref": ref,
#                    "title": title.text,
#                    "pkg": pkgs[0],
#                }
#                cves.append(ret)
#    return cves


def get_packages(package_string):
    """
    Return a list of packages from the input string.
    """

    logging.debug(f"In packages: {package_string}")

    # This will basically remove Updated from an "Updated kernel" package.
    # Capture the package
    # Remove any security, enhancement, bug fix or any combination of those.
    # Match and throw away anything after this up to the severity ().
    initial_re = ".*: (?:Updated )?(.*?)(?:security|enhancement|bug fix).*\\("
    logging.debug(f"packages - perform pattern match {initial_re}")
    match = re.match(initial_re, package_string)

    pkgs = match.group(1) if match else None
    logging.debug(f"After pattern match, pkgs: {pkgs}")

    # Catch all if no packages are found
    if pkgs is None or pkgs.strip(" ") == "":
        pkgs = "Unknown"

    # This will break up multiple packages as a list.
    #   Note: that single packages will be returned as a list.
    pkglist = re.split(", and |, | and ", pkgs.strip(" ").replace(":", "-"))

    logging.debug(f"packages list: {pkglist}")

    return pkglist

def get_fails(oscap_file):
    root = etree.parse(oscap_file)
    ns = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "xhtml": "http://www.w3.org/1999/xhtml", # not actually needed
        "dc": "http://purl.org/dc/elements/1.1/",
    }
    cces = []
    for rule_result in root.findall("xccdf:TestResult/xccdf:rule-result", ns):
        # Current CSV values
        # title,ruleid,result,severity,identifiers,refs,desc,rationale,scanned_date,Justification
        rule_id = rule_result.attrib['idref']
        severity = rule_result.attrib['severity']
        date_scanned = rule_result.attrib['time']
        result = rule_result.find("xccdf:result", ns).text
        logging.debug(f"{rule_id}")
        if result != 'fail':
            logging.info(f"SKIPPING: \'notselected\' rule {rule_id} ")
            continue

        if rule_id == "xccdf_org.ssgproject.content_rule_security_patches_up_to_date":
            logging.info(f"SKIPPING: rule {rule_id} - OVAL check repeats and this deprecated for our findings")
            continue
        # Get the <rule> that corresponds to the <rule-result>
        # This technically allows xpath injection, but we trust XCCDF files from OpenScap enough
        rule = root.find(f".//xccdf:Rule[@id='{rule_id}']", ns)
        title = rule.find("xccdf:title", ns).text

        # This is the identifier that VAT will use. It will never be unset.
        # Values will be of the format UBTU-18-010100 (UBI) or CCI-001234 (Ubuntu)
        # Ubuntu/DISA:
        identifiers = [v.text for v in rule.findall("xccdf:version", ns)]
        if not identifiers:
            # UBI/ComplianceAsCode:
            identifiers = [i.text for i in rule.findall("xccdf:ident", ns)]
        # We never expect to get more than one identifier
        assert len(identifiers) == 1
        logging.debug(f"{identifiers}")
        identifier = identifiers[0]
        # Revisit this if we ever switch UBI from ComplianceAsCode to DISA content

        def format_reference(ref):
            ref_title = ref.find(f"dc:title", ns)
            ref_identifier = ref.find(f"dc:identifier", ns)
            href = ref.attrib.get("href")
            if ref_title is not None:
                assert ref_identifier is not None
                return f"{ref_title.text}: {ref_identifier.text}"
            elif href:
                return f"{href} {ref.text}"

            return ref.text

        # This is now informational only, vat_import no longer uses this field
        references = "\n".join(format_reference(r) for r in rule.findall("xccdf:reference", ns))
        assert references

        rationale = ""
        rationale_element = rule.find("xccdf:rationale", ns)
        # Ubuntu XCCDF has no <rationale>
        if rationale_element:
            rationale = etree.tostring(rationale_element, method="text").strip()

        # Convert description to text, seems to work well:
        description = etree.tostring(rule.find("xccdf:description", ns), method="text").decode('utf8').strip()
        # Cleanup Ubuntu descriptions
        match = re.match(r'<VulnDiscussion>(.*)</VulnDiscussion>', description, re.DOTALL)
        if match:
            description = match.group(1)

        ret = {
            "title": title,
            "ruleid": rule_id,
            "result": result,
            "severity": severity,
            "identifiers": identifiers,
            "refs": references,
            "desc": description,
            "rationale": rationale,
            "scanned_date": date_scanned,
        }
        cces.append(ret)
    return cces

def get_notchecked(oscap_file):
    root = etree.parse(oscap_file)
    ns = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "xhtml": "http://www.w3.org/1999/xhtml", # not actually needed
        "dc": "http://purl.org/dc/elements/1.1/",
    }
    cces_notchecked = []
    for rule_result in root.findall("xccdf:TestResult/xccdf:rule-result", ns):
        # Current CSV values
        # title,ruleid,result,severity,identifiers,refs,desc,rationale,scanned_date,Justification
        rule_id = rule_result.attrib['idref']
        severity = rule_result.attrib['severity']
        date_scanned = rule_result.attrib['time']
        result = rule_result.find("xccdf:result", ns).text
        logging.debug(f"{rule_id}")
        if result != 'notchecked':
            logging.info(f"SKIPPING anything with a result other than 'notchecked'")
            continue

        if rule_id == "xccdf_org.ssgproject.content_rule_security_patches_up_to_date":
            logging.info(f"SKIPPING: rule {rule_id} - OVAL check repeats and this deprecated for our findings")
            continue
        # Get the <rule> that corresponds to the <rule-result>
        # This technically allows xpath injection, but we trust XCCDF files from OpenScap enough
        rule = root.find(f".//xccdf:Rule[@id='{rule_id}']", ns)
        title = rule.find("xccdf:title", ns).text

        # This is the identifier that VAT will use. It will never be unset.
        # Values will be of the format UBTU-18-010100 (UBI) or CCI-001234 (Ubuntu)
        # Ubuntu/DISA:
        identifiers = [v.text for v in rule.findall("xccdf:version", ns)]
        if not identifiers:
            # UBI/ComplianceAsCode:
            identifiers = [i.text for i in rule.findall("xccdf:ident", ns)]
        # We never expect to get more than one identifier
        assert len(identifiers) == 1
        logging.debug(f"{identifiers}")
        identifier = identifiers[0]
        # Revisit this if we ever switch UBI from ComplianceAsCode to DISA content

        def format_reference(ref):
            ref_title = ref.find(f"dc:title", ns)
            ref_identifier = ref.find(f"dc:identifier", ns)
            href = ref.attrib.get("href")
            if ref_title is not None:
                assert ref_identifier is not None
                return f"{ref_title.text}: {ref_identifier.text}"
            elif href:
                return f"{href} {ref.text}"

            return ref.text

        # This is now informational only, vat_import no longer uses this field
        references = "\n".join(format_reference(r) for r in rule.findall("xccdf:reference", ns))
        assert references

        rationale = ""
        rationale_element = rule.find("xccdf:rationale", ns)
        # Ubuntu XCCDF has no <rationale>
        if rationale_element:
            rationale = etree.tostring(rationale_element, method="text").strip()

        # Convert description to text, seems to work well:
        description = etree.tostring(rule.find("xccdf:description", ns), method="text").decode('utf8').strip()
        # Cleanup Ubuntu descriptions
        match = re.match(r'<VulnDiscussion>(.*)</VulnDiscussion>', description, re.DOTALL)
        if match:
            description = match.group(1)

        ret = {
            "title": title,
            "ruleid": rule_id,
            "result": result,
            "severity": severity,
            "identifiers": identifiers,
            "refs": references,
            "desc": description,
            "rationale": rationale,
            "scanned_date": date_scanned,
        }
        cces_notchecked.append(ret)
    return cces_notchecked
