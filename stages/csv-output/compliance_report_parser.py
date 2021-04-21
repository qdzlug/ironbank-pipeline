import xml.etree.ElementTree as etree
root = etree.parse("compliance_output_report.xml")
defs = []
ns = {
    "xccdf": "http://checklists.nist.gov/xccdf/1.2",
    "xhtml": "http://www.w3.org/1999/xhtml", # not actually needed
}
cces = []
for rule_result in root.findall("xccdf:TestResult/xccdf:rule-result", ns):
    # Current CSV values
    # title,ruleid,result,severity,identifiers,refs,desc,rationale,scanned_date,Justification
    rule_id = rule_result.attrib['idref']
    severity = rule_result.attrib['severity']
    date_scanned = rule_result.attrib['time']
    result = rule_result.find("xccdf:result", ns).text
    identifiers = [i.text for i in rule_result.findall("xccdf:ident", ns)]
    rule = root.find(f"//xccdf:Rule[@id='{rule_id}']", ns)
    title = rule.find("xccdf:title", ns).text
    references = [r.text for r in rule.findall("xccdf:reference", ns)]
    rationale = rule.find("xccdf:rationale", ns).text
    # TODO: how to best convert this html to text? text_content()/tostring method=text mostly works
    description = etree.tostring(rule.find("xccdf:description", ns), method="text").strip()
#    print(title, idref, result, severity, identifiers, references, description)
#    rule = [title, rule_id, result, severity, identifiers, references, description, rationale, date_scanned]
    cve_justification = ""
    id = identifiers
    if id in justifications.keys():
        cve_justification = justifications[id]
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
        "Justification": cve_justification,
    }
    cces.append(ret)