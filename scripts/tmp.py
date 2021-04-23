import xml.etree.ElementTree as etree

root = etree.parse("compliance_output_report.xml")
ns = {
    "xccdf": "http://checklists.nist.gov/xccdf/1.2",
    "xhtml": "http://www.w3.org/1999/xhtml", # not actually needed
}
for rule_result in root.findall("xccdf:TestResult/xccdf:rule-result", ns):
    # Current CSV values
    # title,ruleid,result,severity,identifiers,refs,desc,rationale,scanned_date,Justification

    idref = rule_result.attrib.get('idref')
    severity = rule_result.attrib.get('severity')
    result = rule_result.find("xccdf:result", ns).text
    identifiers = [i.text for i in rule_result.findall("xccdf:ident", ns)]
    
    rule = root.find(f"//xccdf:Rule[@id='{idref}']", ns)
    title = rule.find("xccdf:title", ns).text
    references = [r.text for r in rule.findall("xccdf:reference", ns)]
    
    # TODO: how to best convert this html to text? text_content()/tostring method=text mostly works
    description = etree.tostring(rule.find("xccdf:description", ns), method="text").strip()

    print(title, idref, result, severity, identifiers, references, description)