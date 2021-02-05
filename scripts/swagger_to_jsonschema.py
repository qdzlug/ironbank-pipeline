import json
import yaml
import pathlib

empty = {
  "$schema": "https://json-schema.org/draft/2019-09/schema",
  "$id": "https://repo1.dsop.io/ironbank-tools/ironbank-pipeline/schema/empty.schema.json",
  "definitions": {},
  "title": "Empty schema",
  "description": "Empty schema",
  "type": "object",
  "properties": {},
  "required": []
}


def load_swagger_definitions():
    swagger_s = pathlib.Path("vat_findings.swagger.yaml").read_text(encoding="utf-8")
    swagger = yaml.safe_load(swagger_s)
    return swagger["definitions"]


def main():
    definitions = load_swagger_definitions()

    empty["definitions"] = definitions
    empty["properties"] = definitions["Container"]["properties"]

    with pathlib.Path("test.schema.json").open(mode="w") as f:
        json.dump(obj=empty, fp=f)


if __name__ == "__main__":
    main()
