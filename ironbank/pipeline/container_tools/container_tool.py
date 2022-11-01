from dataclasses import dataclass
from abc import ABC


@dataclass
class ContainerTool(ABC):
    authfile: str = None
    docker_config_dir: str = None

    @classmethod
    # return list of [['example', '1'], ['2', '3'], ['a']] as ['example', '1', '2', '3', 'a']
    def _flatten(cls, nested_list: list[any]):
        return [element for sublist in nested_list for element in sublist]

    @classmethod
    # get sub lists of [flag, k=v] and flatten list
    def _generate_arg_list_from_env(cls, flag: str, env_vars: dict) -> list[str]:
        return cls._flatten([[flag, f"{k}={v}"] for k, v in env_vars.items()])

    @classmethod
    # get sub lists of [flag, val] and flatten list
    def _generate_arg_list_from_list(cls, flag: str, arg_list: list[str]):
        return cls._flatten([[flag, val] for val in arg_list])