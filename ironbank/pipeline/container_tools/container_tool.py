from dataclasses import dataclass
from abc import ABC


@dataclass
class ContainerTool(ABC):
    authfile: str = None
    docker_config_dir: str = None

    @classmethod
    # return list of [['example', '1'], ['2', '3'], ['a']] as ['example', '1', '2', '3', 'a']
    def flatten_list(cls, l: list[any]):
        return [element for sublist in l for element in sublist]

    @classmethod
    # get sub lists of [flag, k=v] and flatten list
    def __generate_arg_list_from_env(cls, flag: str, env_vars: dict) -> list[str]:
        return cls.flatten_list([[flag, f"{k}={v}"] for k, v in env_vars.items()])

    @classmethod
    def __generate_arg_list_from_list(cls, flag: str, arg_list: list[str]):
        # get sub lists of [flag, val] and flatten list
        return cls.flatten_list([[flag, val] for val in arg_list])
