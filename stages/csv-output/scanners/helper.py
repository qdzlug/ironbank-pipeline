#!/usr/bin/env python3

import csv
import pathlib


def write_csv_from_dict_list(csv_dir, dict_list, fieldnames, filename):
    """
    Create csv file based off prepared data. The data must be provided as a list
    of dictionaries and the rest will be taken care of.

    """
    filepath = pathlib.Path(csv_dir, filename)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with filepath.open(mode="w", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        if dict_list:
            writer.writerows(dict_list)
