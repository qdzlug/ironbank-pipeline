from ironbank.pipeline.utils import logger,flatten
from ironbank.pipeline.container_tools.container_tool import ContainerTool

log = logger.setup("test_container_tool")


def test_container_tool_init():
    log.info("Test init container with params results in expected values")
    container_tool = ContainerTool(
        authfile="authfile.json", docker_config_dir="docker_config.conf"
    )
    assert container_tool.authfile == "authfile.json"
    assert container_tool.docker_config_dir == "docker_config.conf"

    log.info("Test init container without params results in None as default")
    container_tool = ContainerTool()
    container_tool.authfile = None
    container_tool.docker_config_dir = None


def test_flatten():
    log.info("Test 2d list is successfully flattened")
    assert flatten.flatten([["a", "b"], ["c", "d"], ["e", "f"]]) == [
        "a",
        "b",
        "c",
        "d",
        "e",
        "f",
    ]


def test_generate_arg_list_from_env():
    assert ContainerTool._generate_arg_list_from_env(
        "--test", {"abc": 123, "def": 345}
    ) == ["--test", "abc=123", "--test", "def=345"]


def test_generate_arg_list_from_list():
    assert ContainerTool._generate_arg_list_from_list("--test", ["abc", "def"]) == [
        "--test",
        "abc",
        "--test",
        "def",
    ]
