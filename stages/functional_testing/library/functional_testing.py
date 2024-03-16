import os
import subprocess
import uuid
import time
import sys
import yaml
import json


def print_green(text):
    """Print the given text in green color."""
    print(f"\033[1;32m{text}\033[0m")


def print_red(text):
    """Print the given text in red color."""
    print(f"\033[1;31m{text}\033[0m")


def print_blue(text):
    """Print the given text in blue color."""
    print(f"\033[1;34m{text}\033[0m")


def print_yellow(text):
    """Print the given text in yellow color."""
    print(f"\033[1;33m{text}\033[0m")


# returns true if the <command> output matches the <expected_output> and completes before the timeout
def pod_command_passes(
    _pod_name, command, _expected_output, _kubernetes_namespace, timeout_seconds=90
):
    """Run a command in a pod."""
    try:
        with subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as proc:
            _stdout, _stderr = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        print_red("Command timed out")
        return False
    except subprocess.CalledProcessError:
        print_red("Command execution failed")
        return False
    return True


def pod_completes(pod_name, pod_namespace, max_wait_seconds, check_interval_seconds=2):
    """Check if a pod has completed.

    Return True if it has, False if it has not.
    """
    start_time = time.time()
    status_command = [
        "kubectl",
        "get",
        "pod",
        pod_name,
        "-n",
        pod_namespace,
        "--no-headers",
    ]

    while True:
        elapsed_seconds = time.time() - start_time
        if elapsed_seconds > max_wait_seconds:
            print_red(f"Timeout waiting for pod {pod_name} to complete.")
            return False
        try:
            with subprocess.Popen(
                status_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            ) as proc:
                status_output, _ = proc.communicate()
            status = status_output.decode().strip().split()[2]

            if status == "Completed":
                print_green(f"{elapsed_seconds:.1f}s, {pod_name} status: {status}")
                return True
            print_yellow(f"{elapsed_seconds:.1f}s, {pod_name} status: {status}")
        except subprocess.CalledProcessError as e:
            print_red(f"Error checking status of pod {pod_name}: {e.output.decode()}")
            return False
        time.sleep(check_interval_seconds)


# kill and remove a pod
def cleanup_pod(pod_name, pod_namespace):
    """Kill and remove a pod."""
    stop_cmd = ["kubectl", "delete", "po", pod_name, "-n", pod_namespace, "--force"]
    try:
        subprocess.run(
            stop_cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print_green(
            f"Successfully deleted pod {pod_name} from namespace {pod_namespace}."
        )
    except subprocess.CalledProcessError:
        print_red(f"Failed to delete pod {pod_name} from namespace {pod_namespace}.")


def read_image_from_hardening_manifest(hardening_manifest):
    """Read the image name and tag from the hardening manifest."""
    try:
        with open(hardening_manifest, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
    except FileNotFoundError:
        print_red("Error: hardening_manifest.yaml file not found in the project root")
        return False

    image_name = data["name"]
    image_tag = "ibci-" + str(os.environ["CI_PIPELINE_ID"])
    if image_name is None:
        print_red(
            f"image Name not found in hardening manifest. value for image_name was '{image_name}'"
        )
        return False

    if image_tag is None:
        print_red(
            f"image tag not found in hardening manifest. value for image_name was '{image_tag}'"
        )
        return False

    docker_image = (
        str(os.environ["REGISTRY_PRE_PUBLISH_URL"]) + "/" + image_name + ":" + image_tag
    )

    return docker_image


def generate_pod_manifest(kubernetes_test, image_name):
    """Generate a pod manifest from the kubernetes_test and image_name."""
    # Base pod manifest
    pod_manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "test-pod", "labels": {"app": "test-app"}},
        "spec": {
            "serviceAccountName": "testpod-sa",
            "containers": [{"name": "test-container", "image": image_name}],
        },
    }

    container_spec = pod_manifest["spec"]["containers"][0]

    # Add readinessProbe if present
    if "readinessProbe" in kubernetes_test:
        container_spec["readinessProbe"] = kubernetes_test["readinessProbe"]

    # Add livenessProbe if present
    if "livenessProbe" in kubernetes_test:
        container_spec["livenessProbe"] = kubernetes_test["livenessProbe"]

    # Add env variables if present
    if "env" in kubernetes_test:
        container_spec["env"] = kubernetes_test["env"]

    # Add command if present
    if "command" in kubernetes_test:
        container_spec["command"] = kubernetes_test["command"]

    # Add ports if present
    if "ports" in kubernetes_test:
        container_spec["ports"] = kubernetes_test["ports"]

    # Add args if present
    if "args" in kubernetes_test:
        container_spec["args"] = kubernetes_test["args"]

    # Add resources (requests and limits)
    # Use values from kubernetes_test if present, otherwise use hardcoded defaults
    container_spec["resources"] = kubernetes_test.get(
        "resources",
        {
            "requests": {"cpu": "100m", "memory": "64Mi"},
            "limits": {"cpu": "500m", "memory": "256Mi"},
        },
    )
    # Add imagePullSecrets to the pod spec
    pod_manifest["spec"]["imagePullSecrets"] = [{"name": "my-registry-secret"}]

    return yaml.dump(pod_manifest)


def get_pod_logs(pod_name, pod_namespace, timeout_seconds=10):
    """Get the logs from a pod."""

    try:
        with subprocess.Popen(
            ["kubectl", "logs", pod_name, "-n", pod_namespace],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            logs, _logs_error = proc.communicate(timeout=timeout_seconds)
        return logs.decode().strip()
    except subprocess.TimeoutExpired:
        print_red(f"Fetching logs for pod {pod_name} timed out")
        return ""
    except subprocess.CalledProcessError:
        print_red(f"Error pulling logs for pod {pod_name}")
        return ""


def run_test(
    entrypoint,
    command_timeout,
    pod_name,
    docker_image,
    kubernetes_namespace,
    expected_output=None,
):
    """Run a test."""
    will_check_for_expected_output = False

    if expected_output is not None:
        will_check_for_expected_output = True

    overrides_json = {
        "apiVersion": "v1",
        "spec": {
            "serviceAccount": "testpod-sa"
        }
    }

    # overrides_json = overrides_json.replace('"', '\\"')

    kubectl_command = [f"""kubectl run {pod_name} --overrides={json.dumps(overrides_json)} --image={docker_image} -n {kubernetes_namespace} --command -- {entrypoint}"""]

    # print command information
    print(f"Running test command: {kubectl_command}")
    print(type(kubectl_command))
    print(f"Running test command: {entrypoint}")
    result = subprocess.run(
        kubectl_command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        print("Command executed successfully!")
        print("Output:\n", result.stdout)
    else:
        print("Command failed")
        print("Error:\n", result.stderr)

    print(f"The command timeout is: {command_timeout} seconds")
    print(f"<expected_output> value is: '{expected_output}'")
    if will_check_for_expected_output:
        print(
            f'After {command_timeout} seconds, the pod logs will be checked if they contain the "expected_output"'
        )
    else:
        print(
            f"Because <expected_output> was not specified, after {command_timeout} seconds, the pod logs will be displayed"
        )

    # run the test command
    if not pod_command_passes(
        pod_name,
        kubectl_command,
        expected_output,
        kubernetes_namespace,
        command_timeout,
    ):
        print("Error during pod command execution")

    print_green("Waiting for pod to Complete.")

    if not pod_completes(pod_name, kubernetes_namespace, command_timeout):
        print_yellow(f"Pod {pod_name} did not reach 'Completed' status before timeout.")

    # print the pod logs
    pod_logs = get_pod_logs(pod_name, kubernetes_namespace)
    print(f"Command log dump for pod: <{pod_name}>")
    print_blue(f"\n {pod_logs} \n")
    print(f"end Command log dump for pod: <{pod_name}>")

    # check if expected_output was in logs
    if will_check_for_expected_output:
        expected_output = expected_output.strip()
        if expected_output in pod_logs:
            print_green("Test Passed! Expected output was found in the pod logs.")
        else:
            print_red(
                f"Test Failed: Expected output value '{expected_output}' was not found in pod logs."
            )

    # clean up container
    cleanup_pod(pod_name, kubernetes_namespace)


def main(project_root_dir, kubernetes_namespace):
    """Run the main function."""
    manifest_file_path = f"{project_root_dir}/testing_manifest.yaml"

    hardening_manifest = f"{project_root_dir}/hardening_manifest.yaml"
    # Check for presence of hardenening_manifest.yaml

    docker_image = read_image_from_hardening_manifest(hardening_manifest)

    container_tests = None
    kubernetes_test = None

    # Check for presence of testing_manifest.yaml
    try:
        with open(manifest_file_path, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
            if "command_tests" in data:
                container_tests = data["command_tests"]
            if "kubernetes_test" in data:
                kubernetes_test = data["kubernetes_test"]

    except FileNotFoundError:
        print_red("Error: testing_manifest.yaml file not found in the project root")
        sys.exit(1)

    # iterate through each docker test
    if container_tests is not None:
        test_number = 0

        for container_test in container_tests:
            test_number += 1

            container_test_name = container_test["name"]

            print_yellow("---------------------------------------")
            print_green(f"Beginning Container Test #{test_number}")
            print(f"Test name: {container_test_name}")
            print(f"Test description: {container_test['description']}")

            # Loop through the commands and print command, expected output and timeout

            for command in container_test["commands"]:
                # generate a unique pod name
                pod_name = str(uuid.uuid4())
                print(f"Pod name: {pod_name}")

                # handle expected_output
                expected_output = None
                command_timeout = None
                entrypoint = command["command"]

                if "expected_output" in command:
                    expected_output = command["expected_output"]

                if "timeout_seconds" in command:
                    command_timeout = command["timeout_seconds"]

                # Ensure timeout is never less than 30 seconds
                if command_timeout is None or command_timeout < 45:
                    command_timeout = 45

                run_test(
                    entrypoint,
                    command_timeout,
                    pod_name,
                    docker_image,
                    kubernetes_namespace,
                    expected_output,
                )

    if kubernetes_test is not None:
        pod_manifest_yaml = generate_pod_manifest(kubernetes_test, docker_image)
        with open("/tmp/podmanifest.yaml", "w", encoding="utf-8") as file:
            file.write(pod_manifest_yaml)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 run_image_tests.py <GIT_PROJECT_ROOT_FOLDER>")
        sys.exit(1)

    GIT_PROJECT_ROOT_FOLDER = sys.argv[1]

    # get default gitlab value for the project
    KUBERNETES_NAMESPACE = os.environ.get("NAMESPACE", "functional-testing")

    main(GIT_PROJECT_ROOT_FOLDER, KUBERNETES_NAMESPACE)
