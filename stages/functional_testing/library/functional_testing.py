import os
import subprocess
import uuid
import time
import sys
import yaml


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
    pod_name, command, expected_output, kubernetes_namespace, timeout_seconds=90
):
    """Run a command in a pod."""
    try:
        cmd_list = command.split()
        with subprocess.Popen(
            cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as proc:
            stdout, stderr = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        print_red("Command timed out")
        return False
    except Exception as e:
        print_red(f"Exception encountered running the command: {command}")
        print_red(f"Exception value:\n {e}")
        return False
    return True


def pod_completes(pod_name, pod_namespace, max_wait_seconds, check_interval_seconds=2):
    """Check if a pod has completed within the given time."""
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
            return False
        try:
            with subprocess.Popen(
                status_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            ) as proc:
                status, _ = proc.communicate()
                status = status.decode().split()[2]
            if status == "Completed":
                print(f"{elapsed_seconds:.1f}s, {pod_name} status: {status}")
                return True
            else:
                print(f"{elapsed_seconds:.1f}s, {pod_name} status: {status}")
        except Exception as e:
            print(f"Exception when checking status of pod {pod_name}: {e}")
            return False
        time.sleep(check_interval_seconds)


# kill and remove a pod
def cleanup_pod(pod_name, pod_namespace):
    """Kill and remove a pod."""
    stop_cmd = f"kubectl delete po {pod_name} -n {pod_namespace} --force"
    try:
        subprocess.run(
            stop_cmd.split(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        print(f"Pod {pod_name} in namespace {pod_namespace} deleted.")
    except subprocess.CalledProcessError as e:
        print_red(f"Failed to delete pod {pod_name}: {e}")


def read_image_from_hardening_manifest(hardening_manifest):
    """Read the image name and tag from the hardening manifest."""
    try:
        with open(hardening_manifest, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
        image_name = data["name"]
        image_tag = "ibci-" + str(os.environ.get("CI_PIPELINE_ID", "latest"))
        docker_image = (
            f"{os.environ.get('REGISTRY_PRE_PUBLISH_URL')}/{image_name}:{image_tag}"
        )
        return docker_image
    except FileNotFoundError:
        print_red("Error: hardening_manifest.yaml file not found in the project root")
        return None
    except KeyError as e:
        print_red(f"Key {e} missing in hardening_manifest.yaml")
        return None


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
            "imagePullSecrets": [{"name": "my-registry-secret"}],
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

    return yaml.dump(pod_manifest)


def get_pod_logs(pod_name, pod_namespace, timeout_seconds=10):
    """Get the logs from a pod."""
    logs_command = ["kubectl", "logs", pod_name, "-n", pod_namespace]
    try:
        with subprocess.Popen(
            logs_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as proc:
            logs, _ = proc.communicate(timeout=timeout_seconds)
        return logs.decode().strip()
    except subprocess.TimeoutExpired:
        print_red(f"Fetching logs for pod {pod_name} timed out")
    except Exception as e:
        print_red(f"Exception pulling logs for pod {pod_name}: {e}")
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

    overrides_json = """{
        "apiVersion": "v1",
        "spec": {
            "serviceAccount": "testpod-sa"
        }
    }"""

    # overrides_json = overrides_json.replace('"', '\\"')

    kubectl_command = (
        f"kubectl run {pod_name} "
        f"--overrides='{overrides_json}' "
        f"--image={docker_image} -n {kubernetes_namespace} --command -- {entrypoint}"
    )

    # print command information
    # print(f"Running test command: {kubectl_command}")
    print(f"Running test command: {entrypoint}")
    result = subprocess.run(
        kubectl_command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
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
        print(f"Error during pod command execution")

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
            print_green(f"Test Passed! Expected output was found in the pod logs.")
        else:
            print_red(
                f"Test Failed: Expected output value '{expected_output}' was not found in pod logs."
            )

    # clean up container
    cleanup_pod(pod_name, kubernetes_namespace)


def main(git_project_root_folder, kubernetes_namespace):
    """Run the main function."""
    manifest_file_path = f"{git_project_root_folder}/testing_manifest.yaml"

    hardening_manifest = f"{git_project_root_folder}/hardening_manifest.yaml"
    # Check for presence of hardenening_manifest.yaml

    docker_image = read_image_from_hardening_manifest(hardening_manifest)

    container_tests = None
    kubernetes_test = None

    # Check for presence of testing_manifest.yaml
    try:
        with open(manifest_file_path, "r") as file:
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
                pod_name = uuid.uuid4()
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
        with open("/tmp/podmanifest.yaml", "w") as file:
            file.write(pod_manifest_yaml)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 run_image_tests.py <git_project_root_folder>")
        sys.exit(1)

    git_project_root_folder = sys.argv[1]

    # get default gitlab value for the project
    test_kubernetes_namespace = str(os.environ["NAMESPACE"])

    if test_kubernetes_namespace is None:
        test_kubernetes_namespace = str(os.environ["NAMESPACE"])

    main(git_project_root_folder, test_kubernetes_namespace)
