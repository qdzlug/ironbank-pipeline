from __future__ import annotations


from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from typing import TextIO


@dataclass(slots=True, frozen=True)
class Package:
    name: str
    version: str
    kind: str = field(default=None)
    url: str = field(compare=False, default=None)


class FileParser(ABC):
    @classmethod
    @abstractmethod
    def parse(cls, file: TextIO) -> list[Package]:
        pass
