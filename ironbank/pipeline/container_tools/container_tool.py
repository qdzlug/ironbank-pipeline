from abc import ABC
from dataclasses import dataclass
from typing import Optional

from ironbank.pipeline.utils.flatten import flatten


@dataclass
class ContainerTool(ABC):
    authfile: Optional[str] = None
    docker_config_dir: Optional[str] = None

    @classmethod
    # get sub lists of [flag, k=v] and flatten list
    # helpful for subprocess commands where you need to need to pass multiple environment variable args with the same flag
    # e.g. ['--build-arg', 'abc=123', '--build-arg', 'def=345']
    def _generate_arg_list_from_env(cls, flag: str, env_vars: dict) -> list[str]:
        return flatten([[flag, f"{k}={v}"] for k, v in env_vars.items()])

    @classmethod
    # get sub lists of [flag, val] and flatten list
    # helpful for subprocess commands where you need to need to pass multiple args with the same flag
    # e.g. ['--build-arg', 'abc', '--build-arg', 'def']
    def _generate_arg_list_from_list(cls, flag: str, arg_list: list[str]):
        return flatten([[flag, val] for val in arg_list])
