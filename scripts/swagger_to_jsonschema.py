#!/usr/bin/env python3
#
# Usage (cli):
#
#   python3 swagger_to_jsonschema.py --main-model="Container" --swagger-path="../schema/vat_findings.swagger.yaml"
#   python3 swagger_to_jsonschema.py --main-model="Container" --swagger-path="../schema/vat_findings.swagger.yaml" --dump --schema-filename="generated.schema.json"
#
# Usage (module):
#
#   ```
#   import swagger_to_jsonschema
#
#   schema = swagger_to_jsonschema.generate(
#       main_model="Container",
#       swagger_path="vat_findings.swagger.yaml",
#       dump=True,
#       schema_filename="generated.schema.json",
#   )
#   ```
#

import argparse
import json
import logging
import os
import pathlib

import yaml

_generated_schema = {
    "$schema": "https://json-schema.org/draft/2019-09/schema",
    "$id": "https://repo1.dsop.io/ironbank-tools/ironbank-pipeline/schema/generated.schema.json",
    "definitions": {},
    "title": "Generated schema",
    "description": "Generated schema",
    "type": "object",
    "properties": {},
    "required": [],
}


def _load_swagger_definitions(path=None):
    """
    Load the swagger yaml file and return the definitions.

    """
    swagger_s = pathlib.Path(path).read_text(encoding="utf-8")
    swagger = yaml.safe_load(swagger_s)

    return swagger["definitions"]


def generate(
    main_model=None, swagger_path=None, dump=False, schema_filename="generated.schema.json"
):
    """
    Main entrypoint. Generate json-schema based off the definitions in a swagger spec. The
    swagger spec must be designed so there is a main model that acts as the entrypoint for
    the schema with all sub-models defined. That way the schema can be fully generated from
    the definitions inside the swagger spec.

    Parameters:
        main_model      [required] Name of the main model inside swagger definitions.
        swagger_path    [required] Path and filename of the swagger yaml.
        dump            [optional] Flag to dump schema to file.
        schema_filename [optional] Filename to dump schema to.

    """
    if not main_model:
        raise Exception(
            "No model specified, please specify a swagger model to base schema off"
        )

    if not swagger_path:
        raise Exception("No specified path to swagger spec")

    # Get logging level, set manually when running pipeline
    loglevel = os.environ.get("LOGLEVEL", "INFO").upper()
    if loglevel == "DEBUG":
        logging.basicConfig(
            level=loglevel,
            format="%(levelname)s [%(filename)s:%(lineno)d]: %(message)s",
        )
        logging.debug("Log level set to debug")
    else:
        logging.basicConfig(level=loglevel, format="%(levelname)s: %(message)s")
        logging.info("Log level set to info")

    definitions = _load_swagger_definitions(path=swagger_path)
    logging.info(f"Loaded definitions from {swagger_path}")

    _generated_schema["definitions"] = definitions
    _generated_schema["properties"] = definitions[main_model]["properties"]

    logging.info(f"Defined base schema off of the {main_model} model")

    if dump:
        logging.debug(f"Dumping to {schema_filename}")
        with pathlib.Path(schema_filename).open(mode="w") as f:
            json.dump(obj=_generated_schema, fp=f)

    return _generated_schema


if __name__ == "__main__":
    """
    This can also be used as a command line utility if necessary with all the same command
    line arguments needed to make the generate() function work properly.

    """
    # Arguments
    parser = argparse.ArgumentParser(description="Swagger to json schema arguments")
    parser.add_argument(
        "--main-model",
        type=str,
        required=True,
        help="Swagger model used to construct the base object.",
    )
    parser.add_argument(
        "--swagger-path",
        type=str,
        required=True,
        help="Path to swagger yaml spec.",
    )
    parser.add_argument(
        "--dump",
        action="store_true",
        help="Dump the schema out to a file.",
    )
    parser.add_argument(
        "--schema-filename",
        type=str,
        help="Path and filename to output generated schema.",
    )
    args = parser.parse_args()
    # End arguments

    if args.dump:
        generate(
            main_model=args.main_model,
            swagger_path=args.swagger_path,
            dump=args.dump,
            schema_filename=args.schema_filename,
        )

    else:
        schema = generate(
            main_model=args.main_model,
            swagger_path=args.swagger_path,
        )
        logging.info(json.dumps(schema))
