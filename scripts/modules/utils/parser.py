import re
from pathlib import Path
from dataclasses import dataclass
from utils.sbom import Package
from typing import Optional


@dataclass
class Parser:
    file: Path = None

    def parse(self):
        pass


@dataclass
class YumPackageParser(Package, Parser):
    def parse(self) -> Optional[Package]:
        if self.url.startswith("repodata"):
            return None

        match = re.match(
            r"(?:^|.+/)(?P<name>[^/]+)-(?P<version>[^/-]*-\d+)\.[^/]+\.[^./]+.rpm",
            self.url,
        )

        if not match:
            raise ValueError(f"Could not parse yum URL: {self.url}")

        return (
            Package("rpm", match.group("name"), match.group("version"), self.url)
            if match
            else None
        )


@dataclass
class GoPackageParser(Package, Parser):
    def parse(self) -> Optional[Package]:

        match = re.match(
            r"(?P<name>.*?)/(:?@v/(?P<version>.*?)\.(?P<ext>[^.]+)|(?P<latest>@latest)|(?P<list>list))$",
            self.url,
        )

        if not match:
            raise ValueError(f"Could not parse go URL: {self.url}")
        elif (
            match.group("ext") in ["zip", "info"]
            or match.group("latest")
            or match.group("list")
        ):
            return None
        elif match.group("ext") and match.group("ext") != "mod":
            raise ValueError(f"Unexpected go mod extension: {self.url}")
        else:
            return Package("go", match.group("name"), match.group("version"), self.url)


@dataclass
class NullPackageParser(Package, Parser):
    def parse(self) -> None:
        return None
