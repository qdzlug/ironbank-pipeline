from typing import Any


def flatten(nested_list: list[Any]) -> list[Any]:
    """Return list of [['example', '1'], ['2', '3'], 'z', ['a']] as ['example',
    '1', '2', '3', 'z', 'a']"""
    flattened_list = []
    for item in nested_list:
        flattened_list += item if isinstance(item, list) else [item]
    return flattened_list
