import sys
from artifacts import Artifacts
from oscap import OpenSCAP
from image import Image
from pipeline.utils.envs import Envs
from pipeline.utils.exceptions import GenericSubprocessError
from scanner import Scanner
from log import log


def main() -> None:
    """This function runs the OpenSCAP scans."""

    # pylint does not understand ci_var decorator
    # pylint: disable=comparison-with-callable
    if Envs().skip_openscap != "":
        log.info("Skipping OpenSCAP scan.")
        sys.exit()

    oscap: OpenSCAP

    try:
        oscap = OpenSCAP()
    except ValueError as exc:
        log.error(f"OpenSCAP scan failed: {exc}")
        sys.exit(1)

    try:
        image = Image(oscap)
    except (ValueError, GenericSubprocessError) as exc:
        log.error(f"OpenSCAP scan failed: {exc}")
        sys.exit(1)

    try:
        oscap.download_content(image.base_type, image.security_guide_path)
    except IOError as exc:
        log.error(f"OpenSCAP scan failed: {exc}")
        sys.exit(1)

    scanner: Scanner = Scanner(image)
    try:
        scanner.scan()
    except GenericSubprocessError as exc:
        log.error(f"OpenSCAP scan failed: {exc}")
        sys.exit(1)

    artifcts: Artifacts = Artifacts()
    artifcts.prepare(oscap.version)


if __name__ == "__main__":
    main()
