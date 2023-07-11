import os
import xml.etree.ElementTree as etree


def main() -> None:
    """
    Handle ubi image oval link pointing to v1
    """
    base_image_type = os.environ["BASE_IMAGE_TYPE"]
    if "ubi" in base_image_type:
        scap_guide_path = f"{os.environ['SCAP_CONTENT']}/{os.environ['securityGuide']}"
        ubi_version = base_image_type.split("-", maxsplit=1)[0][-1]
        root = etree.parse(scap_guide_path)
        namespaces = {
            "ds": "http://scap.nist.gov/schema/scap/source/1.2",
            "xlink": "http://www.w3.org/1999/xlink",
        }
        checks = root.find("ds:data-stream/ds:checks", namespaces)
        assert checks
        for check in checks.findall("ds:component-ref", namespaces):
            if (
                check.attrib["id"]
                == "scap_org.open-scap_cref_security-data-oval-com.redhat.rhsa-RHEL{ubi_version}.xml.bz2"
            ):
                check.set(
                    f"{{{namespaces['xlink']}}}href",
                    f"https://access.redhat.com/security/data/oval/v2/RHEL{ubi_version}/rhel-{ubi_version}.oval.xml.bz2",
                )
        root.write("test2.xml")


if __name__ == "__main__":
    main()
