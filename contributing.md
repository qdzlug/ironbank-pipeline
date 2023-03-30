# Contributor guide

## Summaries

This guide provides information regarding contributing to the pipeline, styles to follow and testing information. If you have any questions regarding the content of this document or the ironbank-pipeline, please direct them to @ariel.shnitzer.

### Style

Follow PEP8 but let the formatters/linters do their job. If `black` has nothing left to reformat and `pylint`/`mypy` don't have any complaints, you're covered from a PEP8 perspective as far as we're concerned.

### Testing

We provide many ways to handle mocking/patching things in here, but please follow whatever option you think is most maintainable and extensible. You may find it useful to install an app to provide code coverage by line, but you can also review code coverage for each line you changed in the MR in gitlab after the pipeline completes for your branch.

## Initial setup

- Follow the guide [here](https://python-poetry.org/docs/) to install poetry
- Once poetry is installed, run a `poetry install` in the root of this project.
  - This will create a virtual enviroment, install all the required dependencies to it, and install the `ironbank` folder as a a package
- To enter your virtual environment with all dependencies required for this project, run a `poetry shell`
  - You will need to do this anytime you create a new shell and plan to work in this project

## Formatting and linting tools

Notes:

- All of these tools are installed when running `poetry install` and will be available to run after running a `poetry shell`

While there is some overlap between things each tool will discover, in general you can expect each tool to behave as follows

### Black

Handles formatting to match PEP8.

Black will automatically fix these kinds of issues when run

```python
projects = {"redhat/ubi/ubi8", "twistlock/twistlock", "opensource/python", "distroless/static"}
```

After running `black .`, this gets changed to

```python
projects = {
    "redhat/ubi/ubi8",
    "twistlock/twistlock",
    "opensource/python",
    "distroless/static",
}

```

### Pylint

Lints python code to find breaks in PEP8 convention and general issues. Highly customizable.
Pylint will provide information for these types of issues

**example.py**

```python
def main() -> None:
    exampleText: str = "some text"


if __name__ == "__main__":
    main()
```

```bash
$ pylint example.py
examples.py:1:0: C0116: Missing function or method docstring (missing-function-docstring)
examples.py:2:4: C0103: Variable name "exampleText" doesn't conform to snake_case naming style (invalid-name)
```

### Mypy

Validates type hinting.

Mypy will provide information for these types of issues

**example.py**

```python
example_text: int = "abc"
```

```bash
$ mypy example.py
examples.py:1: error: Incompatible types in assignment (expression has type "str", variable has type "int")
```

### Pylama

Wraps several linters together.

TODO: decide if we're keeping this or getting rid of it in favor of pylint

### Configure pylint/mypy in vscode

- Create a file in the root of this project `.vscode/settings.json`
- Add the following content to it

```json
{
  "python.linting.enabled": true,
  "python.linting.lintOnSave": true,
  "python.linting.mypyEnabled": true,
  "python.linting.pylintEnabled": true
}
```

- Set your interpreter to the one in your poetry env
  - On mac: press `cmd+shift+p` and search for `python select interpreter`
  - Select the python interpreter in your poetry virtualenv (should look something like **~/.../pypoetry/virtualenvs/ibmodules-...**)
    - Note: If you haven't run `poetry install` at any point, this will not work

### Autoreloading in ipython (or jupyter notebooks)

At the start of each session you can run

```python
%load_ext autoreload
%autoreload 2
```

---

If you don't want to do this every time:

- Run

  ```sh
  ipython profile create
  ```

- Open the file that was just created which should be `~/.ipython/profile_default/ipython_config.py`

- Add these two lines to it (or update the lines that are already commented out in the file with these values)

  ```python
  c.TerminalIPythonApp.exec_lines = ['%autoreload 2']
  c.TerminalIPythonApp.extensions = ['autoreload']
  ```

## Style guide

By default, we follow [PEP8](https://peps.python.org/pep-0008) as a style guide. Typically, `black` should be able to automatically fix any formatting issues to align with PEP 8, but it is recommended to still integrate a tool like `pylint` into your editor to catch non-format related issues with PEP 8.

### Naming conventions

- a path to a file is called `<some_name>_path`
- a path to a directory is called `<some_name>_dir`
- we aren't strict with `private` vs. `public` attributes, but if you are going to use them we typically only opt for a single leading underscore for private ones

### Type hinting

- All new/updated files should include a reasonable amount of type hinting
  - All mypy errors should be resolved or commented on in the MR
- avoid using `Any` when adding type hints
  - Exceptions can be made for responses from APIs/services we don't control

### File I/O

- Whenever possible use `Path` objects when working with dirs, files

```python
example_path = Path("example.txt")
```

Best practices when using `Path` objects

#### Seperate dirs/files by comma

```python
# bad
example_path = Path("example/file.txt")

# good
example_path = Path("example", "file.txt")
```

#### Use builtin methods for path traversal

```python
# bad
up_one_dir_from_file = Path(__file__, "..")

# good
up_one_dir_from_file = Path(__file__).parents[0]
# or
up_one_dir_from_file = Path(__file__).parent

```

#### Reading and writing from files

Please do not handle file opening/closing directly such as this example

```python
example_path = open("example.txt")
... # do something with file
example_path.close()

# or

example_path = Path("example.txt").open()
... # do something with file
example_path.close()
```

This can lead to the file being left open if an exception occurs before the file is closed. Please use one of the following two options to handle file read/write.

1. Using with to handle file open/close safely

```python
# reading
example_path = Path("example.txt")
with example_path.open(encoding="utf-8") as f:
  content = f.read()

# writing
content = "example_text"
with example_path.open(encoding="utf-8") as f:
  f.write(content)

```

1. Using builtin Path methods

```python
# reading
content = Path("example.txt").read_text(encoding="utf-8")

# writing
content = "example_text"
Path("example.txt").write_text(content, encoding="utf-8")
```

### Using `with`

As a general rule of thumb, it is recommended to use `with` if `__enter__` and `__exit__` methods are provided for a class and it makes sense.
This prevents needing to handle the case where some step needs to be done if an exception is thrown

<!-- TODO: add examples of __enter__ and __exit__ and how all that works -->

For example:

```python
try:
  f = open("example.txt)
  f.write("example_text")
finally:
  f.close()
```

can be written

```python
with open("example.txt") as f:
  f.write("example_text")
```

Be sure that the `with` is provided at the time of calling the callable that provides an object with `__enter__` and `__exit__` methods
For example, in the code below, the file would not be closed after the `with` block is exited

```python
example_file = open("example.txt")

with example_file as f:
  f.write("example_text")

```

For more info refer to [PEP 343](https://peps.python.org/pep-0343/)

### Use dataclasses

# TODO: talk about this

```python
@dataclass
class Project:
  id_: int
  name: str = "example_name"
  metadata: dict[str, str|int] = field(default_factory=lambda: {})

  def get_metadata(self):
    return self.metadata
```

### Provide a logger for each file and class

Every file should provide a `log` object and every class should have a `_log` class attribute. You should use the `ironbank.pipeline.utils.logger` module for creating these

For example:

```python
from ironbank.pipeline.utils import logger
import logging
from typing import ClassVar

log: logging.Logger = logger.setup("example")

@dataclass
class ExampleClass:
    _log: ClassVar[logging.Logger] = logger.setup("ExampleClass")

```

---

## Testing guide

### Unit testing

#### Basic Example

Below is an example of a function and the unit test for it. `MockResponse` is a mock class that we provide in `ironbank/pipelines/tests/mocks/mock_classes.py` but a very simple version is defined here to prevent confusion.

**example.py**

```python
def example_func(example_data):
    log.info("This is an example")
    return requests.get("https://localhost:8080", data=example_data)
```

**test_example.py**

```python
import pytest
from example import example_func

class MockResponse():
    content: str = "mock_content"

@pytest.fixture
def mock_data():
    return {
        "mock_key": "mock_value"
    }

# fixtures are passed as params
def test_example(monkeypatch, caplog, mock_data):
    # setup
    monkeypatch.setattr(requests, get, lambda url, data: MockResponse(content=data))
    # call the thing you're testing
    result = example_func(mock_data)
    # make assertion against the thing you're testing
    assert isinstance(result, MockResponse)
    assert MockResponse.content == mock_data
    assert "This is an example" in caplog.text
    caplog.clear()

```

#### Mock everything

We want to mock out functionality for anything being called in the thing we're testing.

**Exceptions:**

> Note: We don't want to mock these things directly, but we'll still want to mock callables in the thing we're testing even if they're are only doing these things

- regexes
- string methods
  - i.e. `rstrip`, `split`
- math
- time/dates

For example:

**example.py**

```python
# we're monkeypatching this
def format_request(request: str):
    request = request.rstrip("\n")
    return "_".join(request.split(" "))

# we're testing this
def request_is_valid(request: str):
    # here, format_request will do whatever is defined in the callable for the monkeypatch in `test_validate_request`
    request = format_request(request)
    return request != "bad_request"

```

**test_example.py**

```python

def test_validate_request(monkeypatch):
    monkeypatch.setattr(example, "format_request", lambda request: request)
    # format_request will return its input and won't actually do any formatting
    assert request_is_valid("bad_request") == False
    assert request_id_valid("good_request") == True
```

#### Use existing stuff

<!-- Currently using `conftest.py` at root for reusable fixtures. A project can have multiple conftest.py files placed in a scope where they would be reused. We might want to do that to break out things used by `ironbank` modules and code in the `stages` dir -->

We've created a number of helpful mock classes and fixtures that can be consumed in your tests. Anything defined in **conftest.py** will be auto imported as fixture and just needs to be requested by the test to be used.

Please check **conftest.py** in the root of this project and **ironbank/pipeline/tests/mocks/mock_classes.py** before creating generic fixtures or mock classes to see if they already exist. All new generic fixtures and mock classes should be placed in those files where appropriate.

#### Create mock classes and fixtures

Whether you created the class or not, it typically makes sense to create an additional mock version for each class so you're not having to patch methods multiple times.

For example:

**example.py**

```python
class PipelineResource:
    name: str
    tag: str
    metadata: dict[str, Any]
    extra_data: dict[str, Any] | None = None

    def format_metadata_resource(self):
        self.metadata["resource"] = "_".join(self.metadata["resource"].rstrip("\n").split(" "))

    def validate_metadata(self):
        format_metadata_resource()
        return "\n" not in self.metadata["resource"]

    def truncate_name(self):
        self.name = self.name[:100]

    def set_extra_data(self):
        with Path(self.metadata["extra_json_data"]).open(encoding="utf-8") as f:
            self.extra_data = json.load(f)

    def prep():
        self.truncate_name()
        try:
            self.set_extra_data()
        except FileNotFound as e:
            log.info("Failed to open extra data file")
            sys.exit(1)
        return self.validate_metadata()

```

**ironbank/pipelines/tests/mocks/mock_classes.py**

```python
class MockPipelineResource(PipelineResource):
    name: str = "mock_name"
    tag: str = "mock_tag"
    metadata: dict[str, Any] = field(default_factory=lambda: {"resources": "mock resource"})

    def validate_metadata(self):
        return False

    def truncate_name(self):
        self.name = "mock_truncated_name"

    def set_extra_data(self):
        self.extra_data = {"mock_key": "mock_value"}

    def prep():
        return True

```

**conftest.py**

```python

@pytest.fixture
def raise_():
    """
    Helper function allowing for a lambda to raise an exception
    """
    def raise_exception(e):
        raise e
    return raise_exception

@pytest.fixture
def mock_pipeline_resources(monkeypatch):
    def default_(*args, **kwargs):
        return MockPipelineResource(*args, **kwargs)


    def with_method(method_name, *args, **kwargs):
        monkeypatch.setattr(MockPipelineResource, method_name, PipelineResource.__dict__[method_name])
        return default_(*args, **kwargs)


    return {
        "default": default_
        "with_method": with_method

    }

```

**test_pipeline_resource.py**

```python
# the parameters here are fixtures from conftest.py
def test_pipeline_resource_prep(raise_, mock_pipeline_resources):
    mock_pipeline_resource = mock_pipeline_resources["with_method"]("prep")
    assert mock_pipeline_resource.prep() == False

    monkeypatch.setattr(MockPipelineResource, "set_extra_data", raise_(FileNotFound))
    with pytest.raises(SystemExit) as se:
        mock_pipeline_resource.prep()
    assert se.value.code == 1


def test_pipeline_resource_validate_metadata(mock_pipeline_resources):
    mock_pipeline_resource = mock_pipeline_resources["with_method"]("validate_metadata")
    assert mock_pipeline_resource.validate_metadata() == True

    mock_pipeline_resource = mock_pipeline_resources["with_method"]("validate_metadata", metadata={"resources": "\nmock_invalid_resource_value"})
    assert mock_pipeline_resource.validate_metadata() == False

```

While the initial overhead of creating the mock class and fixture can be significant, it is typically a much more maintainable/extensible path and makes what is happening in the test more obvious. This is more noticeable when there are larger chains of calling/called functions

If we didn't do any of the prep for mocking this, we would have to `monkeypatch` all methods called for every method we're testing. By mocking the class first, we're able to just inherit the mocked methods if they're being called by the method we're testing.

#### Testing gotchas

###### MockClasses with inheritance and classmethods

###### Assertions in pytest.raises blocks

When using `pytest.raises` to test cases where exceptions are called, be sure to keep your exceptions outside of the `with` block or else they will never actually be triggered

```python
# bad
with pytest.raises(SystemExit) as se:
    # this throws an exception which (since this was invoked using with) is caught it in an `__exit__` method that confirms the exception was raised
    example_func_raises_exc("some text")
    # this is skipped
    assert se.value.code == 1

# good
with pytest.raise(SystemExit) as se:
    # this throws an exception, same as above
    example_func_raises_exc("some text")
# se exists outside of the scope of the `with` block
assert se.value.code == 1

```

##### Patching paths are affected when using `from <module> import <something>`

When patching something that was imported in the module you're testing using `from <module> import <thing>`, the path to the patch changes.

Below, there are two examples of how patching looks in each context

**When using `import <module>`, it looks like:**

**example_module.py**

```python
import base64
import pathlib


def example():
    example_path = pathlib.Path('example_path')
    decoded_text = base64.b64encode('example_text')
```

**test_example.py**

```python

@patch('pathlib.Path', new=MockPath)
def test_example():
    monkeypatch.setattr(base64, 'b64encode', lambda x: x)
    example_module.example()

```

**When using `from <module> import <something>`**

**example_module.py**

```python
from base64 import b64encode
from pathlib import Path


def example():
    example_path = Path('example_path')
    decoded_text = b64encode('example_text')
```

**test_example.py**

```python

@patch('example_module.Path', new=MockPath)
def test_example():
    monkeypatch.setattr(example_module, 'b64encode', lambda x: x)
    example_module.example()

```

#### Use `monkeypatch` when mocking functionality for a single function/method

#### Use `@patch` when mocking entire class

Some times we'd like to patch an entire class in our test. Maybe we need to mock a return value that would be an object that calls some methods or it's just easier to mock the entire class or parts of it rather than monkeypatching every method called for a class (which is often the case if you're calling more than one method for a class).

For example:
**example_module.py**

```python

def example(example_path: str):
    example_path = Path(example_path)
    assert example_path.exists()
    with example_path.open(encoding="utf-8") as f:
        content = f.read()
    log.info(example_path.absolute().as_posix())

```

Here we're calling several `Path` methods, and one of those method calls returns another Path object, `absolute()`, which then calls another Path method, `as_posix()`. We're also calling `open` on the `Path` object which returns a `TextIOWrapper` as `f`, which then calls the `read()` method.

You could try to monkeypatch this still, but you'd still need to create some mock class definition to using `with` on `open` and for `absolute` to get the `read` and `as_posix` respectively.

Here's what it looks like if we monkeypatch it.

```python
import example_module

class MockTextIOWrapper():
    def __enter__(self):
        return self
    def __exit__(self, ex_type, ex_value, ex_tb):
        pass
    def read():
        return "mock_read"

class MockPath():
    def as_posix():
        pass

def test_example(monkeypatch):
    monkeypatch.setattr(pathlib.Path, "exists", lambda: True)
    monkeypatch.setattr(pathlib.Path, "open", MockTextIOWrapper())
    monkeypatch.setattr(pathlib.Path, "absolute", MockPath())
    example_module.example("some_path")

```

We can make mocking all of this easier and reusable by skipping monkeypatching altogether and just mocking everything we're using in the `Path` class.
To demonstrate this, we can look at a simplified version of our `MockPath` object that we created in the `ironbank/pipeline/tests/mocks/mock_classes.py` module for this case.

```python
class MockTextIOWrapper():
    def __enter__(self):
        return self
    def __exit__(self, ex_type, ex_value, ex_tb):
        pass
    def read():
        return "mock_read"

class MockPath():
    def open(self):
        return MockTextIOWrapper(self)

    def exists(self):
        return True

    def absolute(self):
        return MockPath()

# this mocks the class definition of Path during instantiation
@patch("pathlib.Path", new=MockPath)
def test_example():
    # all Path methods are overridden by MockPath ones here
    example_module.example('example_path')

    # we can still override functionality with monkeypatch if needed (or even better, provide multiple configurable options for the class with a fixture/helper class)
    monkeypatch.setattr(MockPath, "exists", lambda: False)
    with pytest.raises(AssertionError) as ae:
        example_module.example('example_path')

```

#### Lambdas can be used for simple mocks

For example:

```python
# good
monkeypatch.setattr(<module>, "super_simple_func", lambda a,b: "mock_value")


# this is okay too
def mock_super_simple_func(a, b):
    return "mock_value"
monkeypatch.setattr(<module>, "super_simple_func", mock_super_simple_func)
```

### Integration Testing

<!-- Add stuff here -->

### E2E Testing

<!-- Add information about the kickoff_staging_pipeline dir -->
