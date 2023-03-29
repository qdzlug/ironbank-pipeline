# Contributor guide

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

## Style guide

### Configure pylint/mypy

By default, we follow [PEP8](https://peps.python.org/pep-0008) as a style guide but there are cases where we break conventions from PEP8 listed below. Typically, `black` should be able to automatically fix any formatting issues to align with PEP 8, but it is recommended to still integrate a tool like `pylint` into your editor to catch non-format related issues with PEP 8.

- a path to a file is called `<some_name>_path`
- a path to a directory is called `<some_name>_dir`

avoid using `Any` when using type hints

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

```python
@dataclass
class Project:
  id_: int
  name: str = "example_name"
  metadata: dict[str, str|int] = field(default_factory=lambda: {})

  def get_metadata(self):
    return self.metadata
```

### Type hinting

---

## Testing guide

### Unit testing

#### Basic Example

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

Examples:

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

- MockClasses with inheritance and classmethods

- Assertions in pytest.raises blocks

- Patching is affected by using `from <module> import <thing>`

-

#### Use `@patch` when mocking entire class

#### Use `monkeypatch` when mocking functionality for a single function/method

#### Lambdas can be used for simple mocks

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
