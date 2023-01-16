from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Predicates:
    types: dict = {
            "sbom-cyclonedx-json.json": "cyclonedx",
            "sbom-spdx.xml": "spdx",
            "sbom-spdx-json.json": "spdxjson",
            "sbom-syft-json.json": "https://github.com/anchore/syft#output-formats",
            "vat_response.json": "https://vat.dso.mil/api/p1/predicate/beta1",
            "hardening_manifest.json": "https://repo1.dso.mil/dsop/dccscr/-/raw/master/hardening%20manifest/README.md",
    }
    unattached_predicates: list[str] = [
            "sbom-spdx-tag-value.txt",
            "sbom-cyclonedx.xml",
    ]

    # Defines a map of SBOM output formats provided by syft to their corresponding mediatypes
    @classmethod
    def get_predicate_files(self):
        return {v: k for k, v in self.types.items()}
