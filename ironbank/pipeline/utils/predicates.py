from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Predicates:
    """A class that holds two types of predicates and provides a method to
    invert the mapping of the first type.

    Attributes:
        types (dict): a mapping from file names to their corresponding types.
        unattached_predicates (list[str]): a list of unattached predicates.
    """

    types: dict = field(
        default_factory=lambda: {
            "sbom-cyclonedx-json.json": "cyclonedx",
            "sbom-spdx.xml": "spdx",
            "sbom-spdx-json.json": "spdxjson",
            "sbom-syft-json.json": "https://github.com/anchore/syft#output-formats",
            "vat_response_lineage.json": "https://vat.dso.mil/api/p1/predicate/beta1",
            "hardening_manifest.json": "https://repo1.dso.mil/dsop/dccscr/-/raw/master/hardening%20manifest/README.md",
        }
    )
    unattached_predicates: list[str] = field(
        default_factory=lambda: [
            "sbom-spdx-tag-value.txt",
            "sbom-cyclonedx.xml",
        ]
    )

    # Defines a map of SBOM output formats provided by syft to their corresponding mediatypes
    def get_predicate_files(self):
        """
        Invert the `types` dictionary to map from type to file name.
        Returns:
            dict: The inverted dictionary mapping from types to their corresponding file names.
        """
        return {v: k for k, v in self.types.items()}
