# Defines a map of SBOM output formats provided by syft to their corresponding mediatypes
def get_predicate_types():
    return {
        "sbom-cyclonedx-json.json": "cyclonedx",
        "sbom-spdx.xml": "spdx",
        "sbom-spdx-json.json": "spdxjson",
        "sbom-syft-json.json": "https://github.com/anchore/syft#output-formats",
        "vat_response.json": "https://vat.dso.mil/api/p1/predicate/beta1",
        "hardening_manifest.json": "https://repo1.dso.mil/dsop/dccscr/-/raw/master/hardening%20manifest/README.md",
    }


def get_predicate_files():
    return {v: k for k, v in get_predicate_types().items()}


def get_unattached_predicates():
    return [
        "sbom-spdx-tag-value.txt",
        "sbom-cyclonedx.xml",
    ]
