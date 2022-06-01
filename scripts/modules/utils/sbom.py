from dataclasses import dataclass


@dataclass
class Package:
    type: str = None
    name: str = None
    version: str = None
    url: str = None
