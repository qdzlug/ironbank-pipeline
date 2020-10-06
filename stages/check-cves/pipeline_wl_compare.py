#!/usr/bin/python3
import gitlab
import sys
import json
from bs4 import BeautifulSoup
import re
import os
import argparse
import logging
from distutils import util


gitlab_url = "https://repo1.dsop.io"
dccscr_project_id = 143


def main():
    # Get logging level, set manually when running pipeline
    debug = bool(util.strtobool(os.getenv("DEBUG", default = False)))
    if debug is True:
        logging.basicConfig(level = logging.DEBUG, format = "%(levelname)s [%(filename)s:%(lineno)d]: %(message)s")
        logging.info("Set the log level to debug")
    else:
        logging.basicConfig(level = logging.INFO, format = "%(levelname)s: %(message)s")
        logging.info("Set the log level to info")

    parser = argparse.ArgumentParser(description='DCCSCR processing of CVE reports from various sources')
    parser.add_argument('--image', help='')
    parser.add_argument('--tag',   help='')
    parser.add_argument('--oscap',   help='')
    parser.add_argument('--oval',   help='')
    parser.add_argument('--twistlock',   help='')
    parser.add_argument('--anchore-sec',   help='')
    parser.add_argument('--anchore-gates',   help='')
    parser.add_argument('--glkey', help='')
    parser.add_argument('--proj_branch', help='')
    parser.add_argument('--wl_branch', help='')
    args = parser.parse_args()
    x = pipeline_whitelist_compare(args.image,
                               args.tag,
                               args.oscap,
                               args.oval,
                               args.twistlock,
                               args.anchore_sec,
                               args.anchore_gates,
                               args.glkey,
                               args.proj_branch,
                               args.wl_branch)
    #print(x)
    sys.exit(x)


def pipeline_whitelist_compare(image_name, image_version, oscap, oval, twist, anc_sec, anc_gates, glkey, proj_branch, wl_branch):
    proj = init(dccscr_project_id, glkey)
    image_whitelist = get_complete_whitelist_for_image(proj, image_name, image_version, wl_branch)

    wl_set = set()
    for image in image_whitelist:
        if image.status == "approved":
            wl_set.add(image.vulnerability)

    print("Whitelist Set: ", wl_set)
    print("Whitelist Set Length: ", len(wl_set))

    vuln_set = set()

#   If oscap is equal to None then OpenSCAP was skipped in pipeline and the comparison will also be skipped
    if oscap is not None:
        oscap_cves = get_oscap_fails(oscap)
        # print("Oscap Set Length: ", len(oscap_cves))
        for oscap in oscap_cves:
            vuln_set.add(oscap['identifiers'])

        oval_cves = get_oval(oval)
        # print("Oval Set Length: ", len(oval_cves))
        for oval in oval_cves:
            vuln_set.add(oval)

    tl_cves = get_twistlock_full(twist)
    # print("Twistlock Set Length: ", len(tl_cves))
    for tl in tl_cves:
        vuln_set.add(tl['id'])

    anchore_cves = get_anchore_full(anc_sec)
    # print("Anchore Sec Set Length: ", len(anchore_cves))
    for anc in anchore_cves:
        vuln_set.add(anc['cve'])

    # anchore_gates = report_helpers.get_anchore_gates_full(anc_gates)
    # print("Anchore Gates Set Length: ", len(anchore_cves))
    # for anc in anchore_gates:
    #     print(anc.__dict__)
    #     # vuln_set.add(anc['aofasf'])

    print("Vuln Set: ", vuln_set)
    print("Vuln Set Length: ", len(vuln_set))
    try:
        delta = vuln_set.difference(wl_set)
    except:
        print("There was an error making the vulnerability delta request", file=sys.stderr)
        return 1

    if len(delta) == 0:
        print("ALL VULNERABILITIES WHITELISTED")
        print("Scans are passing 100%")
        return 0
    else:
        print("NON-WHITELISTED VULNERABILITIES FOUND")
        print("Vuln Set Delta: ", delta)
        print("Vuln Set Delta Length: ", len(delta))
        print("Scans are not passing 100%. Vuln Set Delta Length: " + str(len(delta)), file=sys.stderr)

        if proj_branch == 'master':
            return 1
        else:
            # Return 0 exit code even though non-whitelisted vulns found as branch is not master
            return 0

def get_twistlock_full(twistlock_file):
    with open(twistlock_file, mode="r", encoding="utf-8") as twistlock_json_file:
        json_data = json.load(twistlock_json_file)[0]
        twistlock_data = json_data['vulnerabilities']
        cves = []
        if twistlock_data != None:
            for x in twistlock_data:
                cvss = x.get('cvss', '')
                desc = x.get('description', '')
                id = x.get('cve', '')
                link = x.get('link', '')
                packageName = x.get('packageName', '')
                packageVersion = x.get('packageVersion', '')
                severity = x.get('severity', '')
                status = x.get('status', '')
                vecStr = x.get('vecStr', '')
                ret = {
                    'id': id,
                    'cvss': cvss,
                    'desc': desc,
                    'link': link,
                    'packageName': packageName,
                    'packageVersion': packageVersion,
                    'severity': severity,
                    'status': status,
                    'vecStr': vecStr
                }
                cves.append(ret)
    return cves

def get_anchore_full(anchore_file):
    with open(anchore_file,'r', encoding="utf-8") as af:
        json_data = json.load(af)
        image_tag = json_data['imageFullTag']
        anchore_data = json_data['vulnerabilities']
        cves = []
        for x in anchore_data:
            tag = image_tag
            cve = x["vuln"]
            severity = x["severity"]
            package = x["package"]
            package_path = x["package_path"]
            fix = x["fix"]
            url = x["url"]

            ret = {
                'tag': tag,
                'cve': cve,
                'severity': severity,
                'package': package,
                'package_path': package_path,
                'fix': fix,
                'url': url
            }

            cves.append(ret)
        return cves


def get_oval(oval_file):
    oscap = open(oval_file,'r', encoding="utf-8")
    soup = BeautifulSoup(oscap, 'html.parser')
    results_bad = soup.find_all("tr", class_=["resultbadA", "resultbadB"])
    # results_good = soup.find_all("tr", class_=["resultgoodA", "resultgoodB"])

    cves = []
    for x in results_bad: # + results_good:
        # id = x.find("td")
        # result = id.find_next_sibling("td")
        # cls = result.find_next_sibling("td")
        y = x.find_all(target='_blank')
        references = set()
        for t in y:
            references.add(t.text)
        # title = cls.find_next_sibling("td").find_next_sibling("td")

        for ref in references:
            cves.append(ref)
    return cves


def get_oscap_fails(oscap_file):
    with open(oscap_file,'r', encoding="utf-8") as of:
        soup = BeautifulSoup(of, 'html.parser')
        divs = soup.find('div', id="result-details")


        scan_date = soup.find("th", text='Finished at')
        finished_at = scan_date.find_next_sibling("td").text
        # print(finished_at.text)
        regex = re.compile('.*rule-detail-fail.*')
        # id_regex = re.compile('.*rule-detail-.*')
        fails = divs.find_all("div", {"class": regex})
        # all = divs.find_all("div", {"class": id_regex})

        cces = []
        for x in fails:
            title = x.find("h3", {"class": "panel-title"}).text
            table = x.find("table", {"class": "table table-striped table-bordered"})

            ruleid = table.find("td", text="Rule ID").find_next_sibling("td").text
            result = table.find("td", text="Result").find_next_sibling("td").text
            severity = table.find("td", text="Severity").find_next_sibling("td").text
            ident = table.find("td", text="Identifiers and References").find_next_sibling("td")
            if ident.find("abbr"):
                identifiers = ident.find("abbr").text

            references = ident.find_all("a", href=True)
            refs = []
            for j in references:
                refs.append(j.text)

            desc = table.find("td", text="Description").find_next_sibling("td").text
            rationale = table.find("td", text="Rationale").find_next_sibling("td").text

            ret = {
                'title': title,
                # 'table': table,
                'ruleid': ruleid,
                'result': result,
                'severity': severity,
                'identifiers': identifiers,
                'refs': refs,
                'desc': desc,
                'rationale': rationale,
                'scanned_date': finished_at
            }
            cces.append(ret)
        return cces

def get_whitelist_filename(im_name, im_tag):
    dccscr_project = im_name.split('/')
    greylist_name = dccscr_project[-1] + '.greylist'
    dccscr_project.append(greylist_name)
    filename = '/'.join(dccscr_project)
    return filename


def get_whitelist_file_contents(proj, item_path, item_ref):
    try:
        f = proj.files.get(file_path=item_path, ref=item_ref)
    except:
        print("Error retrieving whitelist file:", sys.exc_info()[1], file=sys.stderr)
        print("Whitelist retrieval attempted: " + item_path, file=sys.stderr)
        sys.exit(1)
    try:
        contents = json.loads(f.decode())
    except ValueError as error:
        print("JSON object issue: %s", file=sys.stderr) % error
        sys.exit(1)
    return contents

def get_complete_whitelist_for_image(proj, im_name, im_tag, wl_branch, total_wl=[]):
    filename = get_whitelist_filename(im_name, im_tag)
    contents = get_whitelist_file_contents(proj, filename, wl_branch)

    par_image = contents['image_parent_name']
    par_tag = contents['image_parent_tag']

    # if contents['image_name'] == im_name and contents['image_tag'] == im_tag:
    for x in get_whitelist_for_image(im_name, contents):
        total_wl.append(x)
    if len(par_image) > 0 and len(par_tag) > 0:
        print("Fetching Whitelisted CVEs from parent: " + par_image + ':' + par_tag)
        get_complete_whitelist_for_image(proj, par_image, par_tag, wl_branch)
    # else:
    #     print("Mismatched image name/tag in " + filename + "\nRetrieved Image Name: " + contents['image_name'] + ":" + contents['image_tag'] + "\nSupplied Image Name: " + im_name + ":" + im_tag + "\nCheck parent image tag in your whitelist file.", file=sys.stderr)
    #     sys.exit(1)

    return total_wl


def get_whitelist_for_image(im_name, contents):
    wl = []
    for v in contents['whitelisted_vulnerabilities']:
        tar = Vuln(v, im_name)
        wl.append(tar)
    return wl

def init(pid, gitlab_key):
    gl = gitlab.Gitlab(gitlab_url, private_token=gitlab_key)
    return gl.projects.get(pid)


def set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError


class Vuln:
    vuln_id = ""
    vuln_desc = ""
    vuln_source = ""
    whitelist_source = ""
    status = ""
    approved_date = ""
    approved_by = ""
    justification = ""

    def __repr__(self):
        return "Vuln: " + self.vulnerability + " - " + self.vuln_source + " - " + self.whitelist_source + " - "+ self.status + " - " + self.approved_by

    def __str__(self):
        return "Vuln: " + self.vulnerability + " - " + self.vuln_source + " - " + self.whitelist_source + " - "+ self.status + " - " + self.approved_by

    def __init__(self, v, im_name):
        self.vulnerability = v['vulnerability']
        self.vuln_description = v['vuln_description']
        self.vuln_source = v['vuln_source']
        self.status = v['status']
        self.approved_date = v['approved_date']
        self.approved_by = v['approved_by']
        self.justification = v['justification']
        self.whitelist_source = im_name


if __name__ == "__main__":
    main()  # with if
