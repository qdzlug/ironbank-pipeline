from __future__ import annotations

import json
from pathlib import Path
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(slots=True, frozen=True)
class Package:
    kind: str
    name: str
    version: str
    url: str = field(compare=False, default=None)


class FileParser(ABC):
    @classmethod
    @abstractmethod
    def parse(cls, file: any) -> list[Package]:
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
