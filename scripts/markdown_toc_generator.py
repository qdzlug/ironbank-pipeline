import re
from pathlib import Path

md_file: Path = Path(input("Please provide the markdown file path\n").strip("'\" "))

assert md_file.exists(), f"{md_file} does not exist"

md_file_lines: list[str] = md_file.read_text(encoding="utf-8").split("\n")

header_regex: re.Pattern = re.compile(r"^(#{2,})\s([A-Z].*)")

print("\n\n\n")

for line in md_file_lines:
    line_match: re.Match | None = header_regex.match(line)

    def remove_special_chars(input_str: str) -> str:
        return "".join(re.findall(r"([a-zA-Z0-9\-@#]+)", input_str))

    if line_match:
        print(
            f"{'   '.join('' for t in range(len(str(line_match.group(1)))-1))}1. [{line_match.group(2)}](#{remove_special_chars(line_match.group(2).lower().replace(' ', '-'))})"
        )
