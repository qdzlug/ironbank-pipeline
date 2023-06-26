from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True, frozen=True)
class Package:
    """A simple representation of a software package.

    Attributes:
        kind (str): the type of the package.
        name (str): the name of the package.
        version (str): the version of the package.
        url (str): the url of the package. This attribute is optional and
                    is not used for comparison between `Package` instances.
    """

    kind: str
    name: str
    version: str
    url: str = field(compare=False, default=None)


class FileParser(ABC):
    """Abstract base class for file parsers.

    Contains two class methods: parse and handle_file_obj.
    """

    @classmethod
    @abstractmethod
    def parse(cls, file: any) -> list[Package]:
        """Abstract method that should be implemented by any concrete subclass.

        It should accept a file object or a similar object and return a list of `Package` instances.
        """

    @classmethod
    def handle_file_obj(cls, obj: any) -> list[str]:
        """Handles a file object.

        If the object is a `Path` instance, it checks if the file exists, opens it, and reads its content.
        If the path ends with '.json', it treats the file as a JSON file.
        Otherwise, it reads the file line by line.
        If the input object is not a `Path`, it is returned as is.
        """
        if isinstance(obj, Path):
            if not obj.exists():
                raise FileNotFoundError(f"File not found for path: {obj}")
            with obj.open("r") as f:
                return (
                    json.load(f) if obj.as_posix().endswith(".json") else f.readlines()
                )
        return obj
