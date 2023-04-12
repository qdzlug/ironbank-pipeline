from astroid import nodes
from typing import TYPE_CHECKING, Optional

from pylint.checkers import BaseChecker

if TYPE_CHECKING:
    from pylint.lint import PyLinter


def register(linter: "PyLinter") -> None:
    """This required method auto registers the checker during initialization.
    :param linter: The linter to register the checker to.
    """
    linter.register_checker(SubprocessDecoratorChecker(linter))


class SubprocessDecoratorChecker(BaseChecker):
    name = "subprocess-decorator"
    msgs = {
        "W0001": (
            "Missing subprocess decorator.",
            "subprocess-decorator-missing",
            "All functions directly using subprocess should use the subprocess decorator.",
        ),
    }
    options = ()

    def __init__(self, linter: Optional["PyLinter"] = None) -> None:
        super().__init__(linter)
        self._function_stack = []

    def visit_functiondef(self, node: nodes.FunctionDef) -> None:
        def subprocess_used(function_body: list):
            """Checks for subprocess calls in function body."""
            for line in function_body:
                if (
                    "subprocess.run" in line.as_string()
                    or "subprocess.POpen" in line.as_string()
                ):
                    return True

        self._function_stack.append([])
        if subprocess_used(node.body) and (
            not node.decorators
            or "subprocess_error_handler" not in node.decorators.as_string()
        ):
            self.add_message("subprocess-decorator-missing", node=node)

    def leave_functiondef(self, node: nodes.FunctionDef) -> None:
        self._function_stack.pop()
