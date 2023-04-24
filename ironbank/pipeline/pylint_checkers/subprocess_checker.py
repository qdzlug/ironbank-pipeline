from typing import TYPE_CHECKING, Optional
from astroid import nodes, AstroidError
from astroid.util import Uninferable

from pylint.checkers import BaseChecker

if TYPE_CHECKING:
    from pylint.lint import PyLinter


def register(linter: "PyLinter") -> None:
    """This required method auto registers the checker during initialization.
    :param linter: The linter to register the checker to.
    """
    linter.register_checker(SubprocessChecker(linter))


class SubprocessChecker(BaseChecker):
    """Checker for finding functions that use subprocess and don't include the subprocess_error_handler decorator"""

    name = "subprocess-decorator"
    msgs = {
        "E1500": (
            "Missing subprocess decorator \U0001f974",
            "subprocess-decorator-missing",
            "All functions directly using subprocess should use the subprocess decorator.",
        ),
        "E1501": (
            "Using subprocess with shell=True \U0001f627",
            "using-subprocess-with-shell",
            "Using subprocess with shell=True introduces risks that can mitigated by not creating a subshell and passing a list of args.",
        ),
        "E1502": (
            "Use list of string for subprocess args \U0001f628",
            "use-list-for-subprocess-args",
            "Using subprocess with a args string instead of a list of strings is not recommended.",
        ),
        "E1503": (
            "Using subprocess.Popen without using with \U0001f925",
            "using-popen-without-with",
            "Please consider using `with` when using Popen to allow for safer/easier resource management",
        ),
        "F1504": (
            "Kenn broke something... \U0001f92F",
            "kenn-goofed-on-arg-checks",
            "Inferring the value is weird and scares me. Go debug check_subproc_using_string_arg in subprocess_checkers.py if you see this.",
        ),
    }
    options = ()


    def __init__(self, linter: Optional["PyLinter"] = None) -> None:
        super().__init__(linter)
        self.expr_desc: str = ""
        self._function_stack: list[nodes.FunctionDef] = []
        self.decorator_error_found = False

    def visit_functiondef(self, node: nodes.FunctionDef) -> None:
        """Stores function def."""
        self._function_stack.append(node)

    def leave_functiondef(self, _: nodes.FunctionDef) -> None:
        """Remove function def."""
        self._function_stack.pop()

    def visit_assign(self, node: nodes.Assign) -> None:
        """Checks assignments for subprocess and decorator usage."""
        self.set_expr_desc(node=node)
        self.check_subproc_dec_issues()
        self.check_subproc_popen_not_using_with(node=node)
        self.check_subproc_using_string_arg(node=node)

    def visit_expr(self, node: nodes.Expr) -> None:
        """Checks expressions for subprocess and decorator usage."""
        self.set_expr_desc(node=node)
        self.check_subproc_dec_issues()
        self.check_subproc_popen_not_using_with(node=node)
        self.check_subproc_using_string_arg(node=node)
        if self.expr_desc in ["subprocess.run"] and getattr(node.value, "keywords", None):
            for kwarg in node.value.keywords:
                if "shell=True" == kwarg.as_string():
                    self.add_message("using-subprocess-with-shell", node=node)

    def set_expr_desc(self, node: nodes.Expr | nodes.Assign) -> None:
        self.expr_desc = (
            node.value.func.as_string() if getattr(node.value, "func", None) else ""
        )

    def get_func_def(self) -> nodes.FunctionDef:
        return self._function_stack[-1] if self._function_stack else None

    def check_subproc_using_string_arg(self, node: nodes.ALL_NODE_CLASSES) -> None:
        if self.expr_desc in ["subprocess.run", "subprocess.Popen"]:
            args_ = None
            if getattr(node.value, "args", None):
                args_ = node.value.args[0]
            elif getattr(node.value, "keywords", None):
                for kwarg in node.value.keywords:
                    args_ = kwarg.value if kwarg.arg == "args" else args_
            if args_ and not isinstance(args_, nodes.List):
                # print(args_.root())
                if isinstance(args_, nodes.Name):
                    try:
                        # try to infer type from assigned value
                        inferred_value = next(args_.infer())
                        # look for assignment of var passed as subprocess args in func
                        _, asgns = self.get_func_def().lookup(args_.name)
                        # get assignment statement from lookup
                        asgn_stmt = next(asgns[0].assigned_stmts())
                        # get inferred value from assignment statements if assignment statement isn't already a List
                        inferred_value = next(asgn_stmt.infer()) if not isinstance(asgn_stmt, nodes.List) else asgn_stmt
                        if inferred_value is not Uninferable and not isinstance(inferred_value, nodes.List):
                            self.add_message("use-list-for-subprocess-args", node=node)
                    except AttributeError:
                        self.add_message("kenn-goofed-on-arg-checks", node=node)
                    except AstroidError:
                        self.add_message("kenn-goofed-on-arg-checks", node=node)
                else:
                    self.add_message("use-list-for-subprocess-args", node=node)

    def check_subproc_popen_not_using_with(self, node: nodes.ALL_NODE_CLASSES) -> None:
        # print(self.expr_desc)
        if self.expr_desc == "subprocess.Popen":
            if not getattr(node, "parent", None) or not isinstance(node.parent, nodes.With):
                self.add_message("using-popen-without-with", node=node)

    def check_subproc_dec_issues(self) -> None:
        """Logic for finding if subprocess was used in the function and whether the decorator was added"""
        func_def = self.get_func_def()
        if (
            func_def
            and (self.expr_desc in ["subprocess.run", "subprocess.Popen"])
            and (
                not func_def.decorators
                or "subprocess_error_handler" not in func_def.decorators.as_string()
            )
            and not self.decorator_error_found
        ):
            self.decorator_error_found = True
            self.add_message("subprocess-decorator-missing", node=func_def)
