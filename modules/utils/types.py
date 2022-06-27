from __future__ import annotations


from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from typing import TextIO


class FileParser(ABC):
    @classmethod
    @abstractmethod
    def parse(cls, file: TextIO) -> [Package]:
        pass


@dataclass(slots=True, frozen=True)
class Package:
    kind: str
    name: str
    version: str
    url: str = field(compare=False, default=None)
