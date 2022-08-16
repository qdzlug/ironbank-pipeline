from dataclasses import dataclass


@dataclass
class ReportParser:
    def get_justification(self, justifications: dict):
        return justifications[id] if () in justifications else None
