from dataclasses import dataclass
from abc import ABC


@dataclass
class ContainerTool(ABC):
    authfile: str = None
    docker_config_dir: str = None
