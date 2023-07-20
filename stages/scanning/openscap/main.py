import sys
from dataclasses import dataclass
from artifacts import Artifacts
from envs import Envs
from logger import LoggerMixin
from oscap import OpenSCAP
from image import Image
from pipeline.utils.exceptions import GenericSubprocessError
from scanner import Scanner


@dataclass
class Main(LoggerMixin):
    """This module runs the OpenSCAP scans."""

    def run(self) -> None:
        """This method runs the OpenSCAP scans."""

        if Envs().skip_openscap:
            self._log.info("Skipping OpenSCAP scan.")
            sys.exit()

        oscap: OpenSCAP

        try:
            oscap = OpenSCAP()
        except ValueError as exc:
            self._log.error(f"OpenSCAP scan failed: {exc}")
            sys.exit(1)

        try:
            image = Image(oscap)
        except (ValueError, GenericSubprocessError) as exc:
            self._log.error(f"OpenSCAP scan failed: {exc}")
            sys.exit(1)

        try:
            oscap.download_content(image.base_type, image.security_guide_path)
        except IOError as exc:
            self._log.error(f"OpenSCAP scan failed: {exc}")
            sys.exit(1)

        scanner: Scanner = Scanner(image)
        try:
            scanner.scan()
        except GenericSubprocessError as exc:
            self._log.error(f"OpenSCAP scan failed: {exc}")
            sys.exit(1)

        artifcts: Artifacts = Artifacts()
        artifcts.prepare(oscap.version)


if __name__ == "__main__":
    main = Main()
    main.run()
