from typing import TYPE_CHECKING, Generator, Optional

from astroid import AstroidError, nodes
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
    """Checker for finding functions that use subprocess and don't include the
    subprocess_error_handler decorator."""

    name: str = "subprocess-decorator"
    msgs: dict[str, tuple] = {
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
    options: tuple = ()
    subproc_run: str = "subprocess.run"
    subproc_popen: str = "subprocess.Popen"
    subproc_cmds: list[str] = [subproc_run, subproc_popen]

    def __init__(self, linter: Optional["PyLinter"] = None) -> None:
        super().__init__(linter)
        self._expr_desc: str = ""
        self._function_stack: list[nodes.FunctionDef] = []
        self._decorator_error_found: bool = False

    def visit_functiondef(self, node: nodes.FunctionDef) -> None:
        """Stores function def."""
        self._function_stack.append(node)

    def leave_functiondef(self, _: nodes.FunctionDef) -> None:
        """Remove function def."""
        self._function_stack.pop()
        self._decorator_error_found = False

    def visit_call(self, node: nodes.Call) -> None:
        """Checks expressions for subprocess and decorator usage."""
        self.set_expr_desc(node=node)
        self.check_subproc_dec_issues()
        self.check_subproc_popen_not_using_with(node=node)
        self.check_subproc_using_string_arg(node=node)
        if self._expr_desc in self.subproc_run:
            for kwarg in getattr(node, "keywords", []):
                if "shell=True" == kwarg.as_string():
                    self.add_message("using-subprocess-with-shell", node=node)

    def set_expr_desc(self, node: nodes.Expr | nodes.Assign) -> None:
        """Sets the expression description for a node if it has a function
        attribute."""
        self._expr_desc = node.func.as_string() if getattr(node, "func", None) else ""

    def get_func_def(self) -> nodes.FunctionDef:
        """Gets the current function definition from the function stack."""
        return self._function_stack[-1] if self._function_stack else None

    def get_args_from_node(self, node: nodes.NodeNG) -> nodes.NodeNG:
        """Gets the arguments from the node if the expression description
        matches subprocess commands."""
        args_: nodes.NodeNG | None = None
        if self._expr_desc in self.subproc_cmds:
            args_ = node.args[0] if getattr(node, "args", None) else None
            for kwarg in getattr(node, "keywords", []):
                args_ = kwarg.value if kwarg.arg == "args" else args_
        return args_

    def get_assignments(
        self,
    ) -> Generator[tuple[nodes.AssignName, nodes.NodeNG], None, None]:
        """Yields tuples of assignment name and value nodes from the current
        function definition."""
        # get nodes from func which are either explict assigns or assigns with type hint
        for assign in (
            subnode
            for subnode in self.get_func_def().get_children()
            if isinstance(subnode, (nodes.Assign, nodes.AnnAssign))
        ):
            sub_assign = assign.get_children()
            try:
                assign_name = next(sub_assign)
                assign_val = next(sub_assign)
            except StopIteration:
                continue
            # assign name and val are astroid node types (i.e. AssignName and some astroid node.TYPE)
            # deal with type hint
            # subscript can be a type hint or an assignment of a subscript (e.g. a slice of a list)
            if isinstance(assign_val, nodes.Subscript):
                try:
                    assign_val = next(sub_assign)
                except StopIteration:
                    pass
            yield (assign_name, assign_val)

    def get_inferred_value(
        self, args_: nodes.NodeNG, node: nodes.NodeNG
    ) -> Generator[nodes.NodeNG, None, None]:
        """Attempts to infer the values from arguments and yields those values
        or their assignments."""
        try:
            # try to infer values from argument
            # this will be Uninferable unless the value is passed in directly
            # for example: subprocess.run(['asdfasdf', 'asfasdf])) will return an object of type nodes.List here
            yield from args_.infer()

            # get all assignments (including those with type hint) with name matching args_.name
            # ignore aug assignments
            yield from (
                asgn_val
                for (asgn_name, asgn_val) in self.get_assignments()
                if asgn_name.name == args_.name
            )

        except (AttributeError, AstroidError):
            self.add_message("kenn-goofed-on-arg-checks", node=node)

    def check_subproc_using_string_arg(self, node: nodes.NodeNG) -> None:
        """Checks if a subprocess command is using a string argument instead of
        a list and adds a message if it does."""
        args_: nodes.NodeNG | None = self.get_args_from_node(node)
        if args_ and not isinstance(args_, nodes.List):
            if isinstance(args_, nodes.Name):
                inferred_val_gen = self.get_inferred_value(args_, node)
                inferred_value = next(inferred_val_gen)
                # if inferred value found, skip next iteration
                # else, get last assignment for args passed to subprocess
                inferred_value = inferred_value or list(inferred_val_gen)[-1]

                # skip adding error if Uninferable
                # skip adding error if assignment is to function call (need fallback still)
                # TODO: throw error if Call, unless type hint is provided (can use subscript)
                # TODO: provide fallback to type hint
                if (
                    inferred_value is not Uninferable
                    and not isinstance(inferred_value, nodes.Call)
                    and not isinstance(inferred_value, nodes.List)
                ):
                    self.add_message("use-list-for-subprocess-args", node=node)
            else:
                self.add_message("use-list-for-subprocess-args", node=node)

    def check_subproc_popen_not_using_with(self, node: nodes.NodeNG) -> None:
        """Checks if a subprocess.Popen command is being used outside of a
        'with' statement and adds a message if it is."""
        if self._expr_desc == "subprocess.Popen":
            if not getattr(node, "parent", None) or not isinstance(
                node.parent, nodes.With
            ):
                self.add_message("using-popen-without-with", node=node)

    def check_subproc_dec_issues(self) -> None:
        """Logic for finding if subprocess was used in the function and whether
        the decorator was added."""
        func_def = self.get_func_def()
        if (
            func_def
            and (self._expr_desc in self.subproc_cmds)
            and (
                not func_def.decorators
                or "subprocess_error_handler" not in func_def.decorators.as_string()
            )
            and not self._decorator_error_found
        ):
            self._decorator_error_found = True
            self.add_message("subprocess-decorator-missing", node=func_def)
