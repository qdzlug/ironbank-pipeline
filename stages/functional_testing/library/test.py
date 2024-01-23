import yaml
import os
import subprocess
import uuid
import time
import sys

def print_green(text):
    print(f"\033[1;32m{text}\033[0m")

def print_red(text):
    print(f"\033[1;31m{text}\033[0m")

def print_blue(text):
    print(f"\033[1;34m{text}\033[0m")

def print_yellow(text):
    print(f"\033[1;33m{text}\033[0m")

#returns true if the <command> output matches the <expected_output> and completes before the timeout 
def pod_commmand_passes(pod_name, command, expected_output, kubernetes_namespace, timeout_seconds=90):

    try:        
        stdout, stderr = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate(None)
      
    #return false if there is any other unhandled exception
    except Exception as e:
        print_red(f'Exception encountered running the <command>: {command}')
        print_red(f"Exception value:\n {e}")
        return False
    
    return True

def pod_completes(pod_name, pod_namespace, max_wait_seconds, check_interval_seconds=2):
    start_time = time.time()
    
    status_command =f"kubectl get pod {pod_name} -n {pod_namespace} --no-headers"

    while True:
        elapsed_seconds = time.time() - start_time
        if elapsed_seconds > max_wait_seconds:
            return False
        
        try:
            status, status_error = subprocess.Popen(status_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate(None)
            
            status = status.decode().split()[2]
            
            if status == "Completed":
                print(f"{'{:.1f}'.format(elapsed_seconds)}s, {pod_name} status: {status}")
                return True
            else:
                print(f"{'{:.1f}'.format(elapsed_seconds)}s, {pod_name} status: {status}")

        except Exception as e:
            print(f"Exception when reading status of pod {pod_name}: {e}")
            return False

        time.sleep(check_interval_seconds)

#kill and remove a pod
def cleanup_pod(pod_name, pod_namespace):
    # Ensure to clean up: silently stop the container
    stop_cmd = f"kubectl delete po {pod_name} -n {pod_namespace} --force > /dev/null 2>&1"
    os.system(stop_cmd)
    print(f"Running: {stop_cmd}")

#returns true if image is in local image repo, otherwise returns false
# def image_loaded(docker_image):
#     get_images_command = "docker images --format '{{.Repository}}:{{.Tag}}'"
    
#     try:
#         stdout, stderr = subprocess.Popen(get_images_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate(None)
        
#         images_string = stdout.decode()
#         if docker_image in images_string:
#             return True
#         else:
#             return False
    
#     #return false if timeout is exceeded
#     except Exception as e:
#         print_red(f"Command failed: {get_images_command}")
#         print(f"Exception value was {e}")
    

# #returns true if docker image load <docker_image> succeeds; otherwise returns false
# def pull_docker_image(docker_image, timeout_seconds=60):
#     pull_command = f"docker pull {docker_image}"
    
#     try:
#         stdout, stderr = subprocess.Popen(pull_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate(None, timeout_seconds)
    
#     except TimeoutError as e:
#         print_red(f"'{pull_command}' failed to complete before {timeout_seconds} seconds")
#         return False
    
#     #return false if timeout is exceeded
#     except Exception as e:
#         print(f"Exception while trying to perform '{pull_command}'.\nException value was {e}")
    
#     print_green(f"image '{docker_image}' was loaded succesfully")
#     return True

def read_image_from_hardening_manifest(hardening_manifest):
    try:
        with open(hardening_manifest, 'r') as file:
            data = yaml.safe_load(file)

            image_name = data['name']
            # image_tag = data['tags'][0]
            image_tag = "ibci-" + str(os.environ['CI_PIPELINE_ID'])

    except FileNotFoundError:
        print_red("Error: hardening_manifest.yaml file not found in the project root")
        return False
    
    if (image_name is None):
        print_red(f"image Name not found in hardening manifest. value for image_name was '{image_name}'")
        return False
    
    if (image_tag is None):
        print_red(f"image tag not found in hardening manifest. value for image_name was '{image_tag}'")
        return False

    docker_image = str(os.environ['REGISTRY_PRE_PUBLISH_URL']) + "/" + image_name + ":" + image_tag

    return docker_image

def generate_pod_manifest(kubernetes_test, image_name):
    # Base pod manifest
    pod_manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "test-pod",
            "labels": {
                "app": "test-app"
            }
        },
        "spec": {
            "serviceAccountName": "testpod-sa",
            "containers": [{
                "name": "test-container",
                "image": image_name
            }],
            "nodeSelector": {
                "ironbank": "runtime"
            },
            "tolerations": [{
                "key": "ironbank",
                "operator": "Equal",
                "value": "runtime",
                "effect": "NoSchedule"
            }]
        }
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
    container_spec["resources"] = kubernetes_test.get("resources", {
        "requests": {
            "cpu": "100m",
            "memory": "64Mi"
        },
        "limits": {
            "cpu": "500m",
            "memory": "256Mi"
        }
    })
    # Add imagePullSecrets to the pod spec
    pod_manifest["spec"]["imagePullSecrets"] = [{"name": "my-registry-secret"}]

    return yaml.dump(pod_manifest)

def get_pod_logs(pod_name, pod_namespace, timeout_seconds=10):
    logs_command = f"kubectl logs {pod_name} -n {pod_namespace}"

    try:
        logs, logs_error = subprocess.Popen(logs_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate(None, timeout_seconds)
    
    except TimeoutError as e:
        print_red(f"'{logs_command}' failed to complete before {timeout_seconds} seconds")
        return False
    
    except Exception as e:
        print_red(f"unhandled exception trying to pull logs for pod {pod_name}")
        print_red(f"Exceprion was: {e}")

    return logs.decode().strip()

def run_test(entrypoint, command_timeout, pod_name, docker_image, kubernetes_namespace, expected_output=None):
    will_check_for_expected_output = False
    
    if(expected_output is not None):
        will_check_for_expected_output = True
    
    overrides_json = """{
        "apiVersion": "v1",
        "spec": {
            "serviceAccount": "testpod-sa",
            "nodeSelector": {
                "ironbank": "runtime"
            },
            "tolerations": [
                {
                    "key": "ironbank",
                    "operator": "Equal",
                    "value": "runtime",
                    "effect": "NoSchedule"
                }
            ]
        }
    }"""

    # overrides_json = overrides_json.replace('"', '\\"')

    kubectl_command = (
        f"kubectl run {pod_name} "
        f"--overrides='{overrides_json}' "
        f"--image={docker_image} -n {kubernetes_namespace} -- {entrypoint}"
    )



    # generate the kubectl command
    # kubectl_command = f"kubectl run {pod_name} --image={docker_image} -n {kubernetes_namespace} -- {entrypoint}"

    #print command information
    # print(f"Running test command: {kubectl_command}")
    print(f"Running test command: {entrypoint}")
    result = subprocess.run(kubectl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        print("Command executed successfully!")
        print("Output:\n", result.stdout)
    else:
        print("Command failed")
        print("Error:\n", result.stderr)

    print(f"The command timeout is: {command_timeout} seconds")
    print(f"<expected_output> value is: '{expected_output}'")
    if(will_check_for_expected_output):
        print(f'After {command_timeout} seconds, the pod logs will be checked if they contain the "expected_output"')
    else:
        print(f'Because <expected_output> was not specified, after {command_timeout} seconds, the pod logs will be displayed')

    #run the test command
    if not pod_commmand_passes(pod_name, kubectl_command, expected_output, kubernetes_namespace, command_timeout):
        print(f"Error during pod command execution")
    
    print_green("Waiting for pod to Complete.")

    if not pod_completes(pod_name, kubernetes_namespace, command_timeout):
        print_yellow(f"Pod {pod_name} did not reach 'Completed' status before timeout.")

    #print the pod logs
    pod_logs = get_pod_logs(pod_name, kubernetes_namespace)
    print(f"Command log dump for pod: <{pod_name}>")
    print_blue(f"\n {pod_logs} \n")
    print(f"end Command log dump for pod: <{pod_name}>")

    #check if expected_output was in logs
    if(will_check_for_expected_output):
        expected_output = expected_output.strip()
        if expected_output in pod_logs:
            print_green(f"Test Passed! Expected output was found in the pod logs.")
        else:
            print_red(f"Test Failed: Expected output value '{expected_output}' was not found in pod logs.")
        
    #clean up container
    cleanup_pod(pod_name, kubernetes_namespace)

def main(git_project_root_folder, kubernetes_namespace):
    manifest_file_path = f"{git_project_root_folder}/testing_manifest.yaml"

    hardening_manifest = f"{git_project_root_folder}/hardening_manifest.yaml"
    # Check for presence of hardenening_manifest.yaml

    docker_image = read_image_from_hardening_manifest(hardening_manifest)

    #make sure docker image is loaded
    # if not image_loaded(docker_image):
    #     print_yellow(f"docker image '{docker_image}' was not found in the local repo.")
        
    #     print(f"Attempting to pull docker image '{docker_image}'")
    #     if pull_docker_image(docker_image):
    #         print_green(f"{docker_image} pulled successfully.")
    #     else:
    #         print_red(f"{docker_image} could not be pulled; exiting")
    #         sys.exit(1)

    container_tests = None
    kubernetes_test = None

    # Check for presence of testing_manifest.yaml
    try:
        with open(manifest_file_path, 'r') as file:
            data = yaml.safe_load(file)
            if 'docker_tests' in data:
                container_tests = data['docker_tests']
            if 'kubernetes_test' in data:
                kubernetes_test = data['kubernetes_test']
                
    except FileNotFoundError:
        print_red("Error: testing_manifest.yaml file not found in the project root")
        sys.exit(1)

    #iterate through each docker test
    if container_tests is not None:
        test_number = 0

        for container_test in container_tests:
            test_number+=1

            container_test_name = container_test['name']
            
            print_yellow("---------------------------------------")
            print_green(f"Beginning Container Test #{test_number}")
            print(f"Test name: {container_test_name}")
            print(f"Test description: {container_test['description']}")

            # Loop through the commands and print command, expected output and timeout

            for command in container_test["commands"]:
                
                #generate a unique pod name
                pod_name = uuid.uuid4()
                print(f"Pod name: {pod_name}")

                #handle expected_output
                expected_output = None
                command_timeout = None
                entrypoint = command['command']

                if 'expected_output' in command:
                    expected_output = command['expected_output']

                if 'timeout_seconds' in command:
                    command_timeout = command['timeout_seconds']

                # Ensure timeout is never less than 30 seconds
                if command_timeout is None or command_timeout < 45:
                    command_timeout = 45

                run_test(entrypoint, command_timeout, pod_name, docker_image, kubernetes_namespace, expected_output)
    
    if kubernetes_test is not None:
        pod_manifest_yaml = generate_pod_manifest(kubernetes_test, docker_image)
        with open("/tmp/podmanifest.yaml", "w") as file:
            file.write(pod_manifest_yaml)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 run_image_tests.py <git_project_root_folder>")
        sys.exit(1)

    git_project_root_folder = sys.argv[1]

    #get default gitlab value for the project
    test_kubernetes_namespace = str(os.environ['NAMESPACE'])

    if test_kubernetes_namespace is None:
        test_kubernetes_namespace = str(os.environ['NAMESPACE'])

    main(git_project_root_folder, test_kubernetes_namespace)