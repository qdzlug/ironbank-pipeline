from __future__ import annotations


from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import json
from pathlib import Path
from typing import TextIO


@dataclass(slots=True, frozen=True)
class Package:
    kind: str
    name: str
    version: str
    url: str = field(compare=False, default=None)


class FileParser(ABC):
    @classmethod
    @abstractmethod
    def parse(cls, file: TextIO) -> list[Package]:
        pass

    @classmethod
    def handle_file_obj(cls, obj: any) -> list[str]:
        if isinstance(obj, Path):
            if not obj.exists():
                raise FileNotFoundError(f"File not found for path: {obj}")
            with obj.open("r") as f:
                return (
                    json.load(f) if obj.as_posix().endswith(".json") else f.readlines()
                )
        return obj
