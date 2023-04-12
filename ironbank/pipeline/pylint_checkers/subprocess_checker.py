from typing import TYPE_CHECKING, Optional
from astroid import nodes

from pylint.checkers import BaseChecker

if TYPE_CHECKING:
    from pylint.lint import PyLinter


def register(linter: "PyLinter") -> None:
    """This required method auto registers the checker during initialization.
    :param linter: The linter to register the checker to.
    """
    linter.register_checker(SubprocessDecoratorChecker(linter))


class SubprocessDecoratorChecker(BaseChecker):
    """Checker for finding functions that use subprocess and don't include the subprocess_error_handler decorator"""

    name = "subprocess-decorator"
    msgs = {
        "E1500": (
            "Missing subprocess decorator.",
            "subprocess-decorator-missing",
            "All functions directly using subprocess should use the subprocess decorator.",
        ),
    }
    options = ()

    def __init__(self, linter: Optional["PyLinter"] = None) -> None:
        super().__init__(linter)
        self._function_stack: list[nodes.FunctionDef] = []

    def visit_functiondef(self, node: nodes.FunctionDef) -> None:
        """Stores function def."""
        self._function_stack.append(node)

    def leave_functiondef(self, _: nodes.FunctionDef) -> None:
        """Remove function def."""
        self._function_stack.pop()

    def visit_expr(self, node: nodes.Expr) -> None:
        """Checks expressions for subprocess run."""
        func_def = self._function_stack[-1] if self._function_stack else None
        expr_desc = (
            node.value.func.as_string() if getattr(node.value, "func", None) else None
        )
        if (
            func_def
            and expr_desc
            and (expr_desc in ["subprocess.run", "subprocess.Popen"])
            and (
                not func_def.decorators
                or "subprocess_error_handler" not in func_def.decorators.as_string()
            )
        ):
            self.add_message("subprocess-decorator-missing", node=func_def)
