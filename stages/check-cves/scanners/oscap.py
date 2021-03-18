import re
from bs4 import BeautifulSoup


def get_oval(oval_file):
    cves = list()
    with oval_file.open(mode="r", encoding="utf-8") as of:
        soup = BeautifulSoup(of, "html.parser")
        results_bad = soup.find_all("tr", class_=["resultbadA", "resultbadB"])

        for x in results_bad:

            id = x.find("td")
            result = id.find_next_sibling("td")
            cls = result.find_next_sibling("td")
            title = cls.find_next_sibling("td").find_next_sibling("td")
            y = x.find_all(target="_blank")
            references = set()
            for t in y:
                references.add(t.text)
            for ref in references:
                pkgs = get_packages(title.text)
                ret = {
                    "id": id.text,
                    "result": result.text,
                    "cls": cls.text,
                    "ref": ref,
                    "title": title.text,
                    "pkg": pkgs[0],
                }
                cves.append(ret)
    return cves


def get_packages(package_string):
    """
    Return a list of packages from the input string.
    """

    print(f"In packages: {package_string}")

    # This will basically remove Updated from an "Updated kernel" package.
    # Capture the package
    # Remove any security, enhancement, bug fix or any combination of those.
    # Match and throw away anything after this up to the severity ().
    initial_re = ".*: (?:Updated )?(.*?)(?:security|enhancement|bug fix).*\\("
    print(f"packages - perform pattern match {initial_re}")
    match = re.match(initial_re, package_string)

    pkgs = match.group(1) if match else None
    print(f"After pattern match, pkgs: {pkgs}")

    # Catch all if no packages are found
    if pkgs is None or pkgs.strip(" ") == "":
        pkgs = "Unknown"

    # This will break up multiple packages as a list.
    #   Note: that single packages will be returned as a list.
    pkglist = re.split(", and |, | and ", pkgs.strip(" ").replace(":", "-"))

    print(f"packages list: {pkglist}")

    return pkglist


def get_fails(oscap_file):
    with oscap_file.open("r", encoding="utf-8") as of:
        soup = BeautifulSoup(of, "html.parser")
        divs = soup.find("div", id="result-details")

        scan_date = soup.find("th", text="Finished at")
        finished_at = scan_date.find_next_sibling("td").text

        regex = re.compile(".*rule-detail-fail.*")

        fails = divs.find_all("div", {"class": regex})

        cces = []
        for x in fails:
            title = x.find("h3", {"class": "panel-title"}).text
            table = x.find("table", {"class": "table table-striped table-bordered"})

            ruleid = table.find("td", text="Rule ID").find_next_sibling("td").text
            result = table.find("td", text="Result").find_next_sibling("td").text
            severity = table.find("td", text="Severity").find_next_sibling("td").text
            ident = table.find(
                "td", text="Identifiers and References"
            ).find_next_sibling("td")
            if ident.find("abbr"):
                identifiers = ident.find("abbr").text

            references = ident.find_all("a", href=True)
            refs = []
            for j in references:
                refs.append(j.text)

            desc = table.find("td", text="Description").find_next_sibling("td").text
            rationale = table.find("td", text="Rationale").find_next_sibling("td").text

            ret = {
                "title": title,
                "ruleid": ruleid,
                "result": result,
                "severity": severity,
                "identifiers": identifiers,
                "refs": refs,
                "desc": desc,
                "rationale": rationale,
                "scanned_date": finished_at,
            }
            cces.append(ret)
        return cces


def get_notchecked(oscap_file):
    with oscap_file.open("r", encoding="utf-8") as of:
        soup = BeautifulSoup(of, "html.parser")
        divs = soup.find("div", id="result-details")

        scan_date = soup.find("th", text="Finished at")
        finished_at = scan_date.find_next_sibling("td").text

        regex = re.compile(".*rule-detail-notchecked.*")

        notchecked = divs.find_all("div", {"class": regex})

        cces_notchecked = []
        for x in notchecked:
            title = x.find("h3", {"class": "panel-title"}).text
            table = x.find("table", {"class": "table table-striped table-bordered"})

            ruleid = table.find("td", text="Rule ID").find_next_sibling("td").text
            result = table.find("td", text="Result").find_next_sibling("td").text
            severity = table.find("td", text="Severity").find_next_sibling("td").text
            ident = table.find(
                "td", text="Identifiers and References"
            ).find_next_sibling("td")
            if ident.find("abbr"):
                identifiers = ident.find("abbr").text

            references = ident.find_all("a", href=True)
            refs = []
            for j in references:
                refs.append(j.text)

            desc = table.find("td", text="Description").find_next_sibling("td").text
            rationale = table.find("td", text="Rationale").find_next_sibling("td").text

            ret = {
                "title": title,
                "ruleid": ruleid,
                "result": result,
                "severity": severity,
                "identifiers": identifiers,
                "refs": refs,
                "desc": desc,
                "rationale": rationale,
                "scanned_date": finished_at,
            }
            cces_notchecked.append(ret)
        return cces_notchecked
