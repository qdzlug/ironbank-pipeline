## Table of Contents

- [Functional Testing Stage Documentation](#functional-testing-stage-documentation)
  - [Overview](#overview)
  - [Workflow Diagram](#workflow-diagram)
  - [Steps and Commands](#steps-and-commands)
  - [Rules](#rules)
- [templates.sh Script Documentation](#templatessh-script-documentation)
  - [Overview](#overview-1)
  - [Detailed Explanation](#detailed-explanation)
  - [Usage](#usage)
- [functional_testing.py Script Documentation](#testpy-script-documentation)
  - [Overview](#overview-2)
  - [Detailed Explanation](#detailed-explanation-1)
  - [Usage](#usage-1)
- [Creation of podmanifest.yaml in functional_testing.py](#creation-of-podmanifestyaml-in-testpy)
  - [How it's Achieved](#how-its-achieved)
- [run_k8s_test.sh Script Documentation](#run_k8s_testssh-script-documentation)
  - [Overview](#overview-3)
  - [Detailed Explanation](#detailed-explanation-2)
  - [Usage](#usage-2)
- [testing_manifest.yaml User Documentation](#testing_manifestyaml-user-documentation)
  - [Command Probe Tests](#command-probe-tests)
  - [Kubernetes Test](#kubernetes-test)
  - [Example testing_manifest.yaml template](#example-testing_manifestyaml-template)


# Functional Testing Stage Documentation

The functional testing stage is a crucial step in the Continuous Integration/Continuous Deployment (CI/CD) process. It ensures that images, once built, function as expected. This step not only assures the functionality of the images but also helps in building trust among the users.

## Overview

In this stage, the pipeline:
1. Clones the repository.
2. Sets up authentication for the package.
3. Installs necessary dependencies. (not necessary if baked into the image and in disconnected run)
4. Views the Kubernetes configuration.
5. Sets up Kubernetes resources for functional testing.
6. Executes the main testing script.
7. Optionally runs a Kubernetes test if a specific manifest file exists.

## Architecture Diagram

Here is a architecture diagram

![Testing Stage](stages/functional_testing/images/testingstage.jpg)


## Steps and Commands

1. **Sourcing the Templates**:
   ```bash
   source ${PIPELINE_REPO_DESTINATION}/stages/functional_testing/library/templates.sh
   ```

2. **Setting up Kubernetes Resources**:
   ```bash
   setup_k8s_resources "$NAMESPACE" 
   ```

3. **Executing the Main Test Script**:
   ```bash
   python3 ${PIPELINE_REPO_DESTINATION}/stages/functional_testing/library/functional_testing.py $CI_PROJECT_DIR
   ```

4. **Conditional Kubernetes Test**:
   ```bash
   if [[ -f "/tmp/podmanifest.yaml" ]]; then ${PIPELINE_REPO_DESTINATION}/stages/functional_testing/library/run_k8s_test.sh; fi
   ```

## Rules:
- The testing stage will always run if `testing_manifest.yaml` exists.
- Otherwise, the testing stage will never run and the pipeline continues as is.

# `templates.sh` Script Documentation

The `templates.sh` script provides environment settings and helper functions that assist in setting up debugging and Kubernetes resources.

## Overview

- **Debug Settings**: The script contains conditions that enable debugging mode if certain environment variables or conditions are met.
- **Error Handling**: Provides a mechanism to catch and display errors in a readable format.
- **Kubernetes Resources**: Contains a function to setup Kubernetes resources such as Docker registry secrets.

## Detailed Explanation

### Debugging and Error Handling

1. The script checks if it's being run standalone. If so, it provides an informative message and exits.
2. If the `DEBUG_ENABLED` environment variable is set to `true` or if certain merge request conditions are met, the script will enable bash debugging with the `-x` option.
3. The `trap` command is used to catch errors and display an error message with the file and line number where the error occurred.

### Kubernetes Resources (`setup_k8s_resources` function)

1. **Namespace and Docker Credentials**: The function accepts a namespace argument. If they're not set, it displays a message and creates the namespace.
2. **Docker Registry Secret**: If a secret named `my-registry-secret` doesn't exist in the specified namespace, it creates one using the environment variables from pipeline CICD vars.
2. **Service Account**: If a service account named `test-pod-sa` doesn't exist in the specified namespace, it creates one and annotates the service account with the secret so that it can pull image from the registry1.

# `functional_testing.py` Script Documentation

The `functional_testing.py` script is designed to test images by running them as pods in a Kubernetes environment. It performs various checks based on a testing manifest, and also ensures the Docker image is loaded and ready for testing.

## Overview

- **Color Printing Functions**: The script provides helper functions to print messages in different colors for better readability.
- **Command Execution**: Contains functions to execute shell commands and Kubernetes commands.
- **Pod Manifest Generation**: Generates a Kubernetes pod manifest based on the testing manifest.
- **Test Execution**: Contains the main logic to run the tests described in the testing manifest.
- **Main Execution**: The script's entry point, where it checks for the necessary arguments and initiates the testing process.

## Detailed Explanation

### Command Execution

1. `pod_command_passes`: Executes a command on a pod and checks if its output matches the expected output.
2. `pod_completes`: Waits for a pod to reach the "Completed" status.
3. `get_pod_logs`: Retrieves the logs of a specified pod.
4. `cleanup_pod`: Deletes a specified pod from the Kubernetes cluster.

### Kubernetes Manifest Generation

The `generate_pod_manifest` function generates a Kubernetes pod manifest based on the details in the testing manifest. This includes setting readiness probes, liveness probes, environment variables, resource limits, ports, and image pull secrets.

### Test Execution

The `run_test` function is the main test execution function. It:

1. Initializes the pod with the image.
2. Waits for the pod to complete.
3. Retrieves the pod logs.
4. Compares the pod logs with the expected output (if specified).

# Creation of `podmanifest.yaml` in `functional_testing.py`

The `functional_testing.py` script encompasses an essential capability: the dynamic generation of a Kubernetes Pod manifest, specifically designed for the tests it's set to run. This manifest is subsequently written to `/tmp/podmanifest.yaml`.

## How it's Achieved:

### 1. **Function: `generate_pod_manifest(kubernetes_test, image_name)`**

This function crafts the foundational structure of a Kubernetes Pod manifest and then populates it according to the provided image and any Kubernetes-specific tests present in the `testing_manifest.yaml`.

- **Base Pod Manifest**:
  - A rudimentary structure for the Pod manifest is laid out with placeholders. This encompasses:
    - Pod API version and type.
    - Metadata such as name and labels.
    - A basic container specification with a placeholder for the image.

- **Customization**:
  - The function subsequently adjusts this primary manifest based on the `kubernetes_test` input:
    - If defined in the `kubernetes_test`, Readiness and Liveness Probes are incorporated.
    - If present, Environment variables (`env`) are appended and similarly ports, commands, and args.
    - Resources, such as CPU and Memory requests and limits, are stipulated either from the `kubernetes_test` or through hardcoded defaults.
    - To ensure the image can be fetched from a private registry, ImagePullSecrets is appended to the Pod spec.

- **Return**:
  - The function culminates by returning the manifest in YAML format.

### 2. **Usage in `main()` Function**:

Post the identification of the image to be tested within the `main()` function, the script ascertains if there are any Kubernetes-oriented tests to be executed. If affirmative, it invokes the `generate_pod_manifest` function to craft the manifest. This manifest is then inscribed to `/tmp/podmanifest.yaml`.

```python
pod_manifest_yaml = generate_pod_manifest(kubernetes_test, docker_image)
with open("/tmp/podmanifest.yaml", "w") as file:
    file.write(pod_manifest_yaml)
```

# `run_k8s_tests.sh` Script Documentation

The `run_k8s_tests.sh` script deploys a Kubernetes pod based on a manifest file and monitors its status to ensure it runs correctly. The script is designed to validate the functionality of the container image within a Kubernetes environment.

## Overview

1. **Variables Initialization**: Setting up default namespace and unique pod name.
2. **Print Functions**: Helper functions to display messages in various colors.
3. **Script Execution**: The core logic for deploying and monitoring the pod, including error handling.
4. **Cleanup**: Deletes the deployed pod at the end.

## Detailed Explanation

### Variables Initialization

- `NAMESPACE`: The Kubernetes namespace where the pod will be deployed.
- `UNIQUE_POD_NAME`: A unique pod name generated using `uuidgen`.

### Script Execution

1. **Namespace Validation**: Assumes that the namespace specified by the `NAMESPACE` variable exists.
2. **Extract Image from Manifest**: Reads the image name from the `/tmp/podmanifest.yaml` file.
3. **Pod Deployment**: Modifies the pod name in the manifest and deploys the pod to the Kubernetes cluster.
4. **Pod Monitoring**: Monitors the pod's status for 3 minutes. If the pod consistently fails or runs, it breaks out of the monitoring loop early.
5. **Pod Description**: Describes the pod after waiting the "initialDelaySeconds" passed into the testing_manifests if present to fetch details about its deployment and potential issues.
6. **Fetch Pod Logs**: Retrieves the logs of the deployed pod.
7. **Error Handling**: If the pod doesn't reach the "Running" or "Completed" state, scripts errors and instructs to look into pod logs, events, and exec logs
8. **Final Status**: Towards the end, script will show the final pod status

### Cleanup

- The deployed pod is deleted from the Kubernetes namespace.
- The script ends by checking the final status of the pod and provides an appropriate exit code.

# `testing_manifest.yaml` User Documentation

The `testing_manifest.yaml` file plays a crucial role in the functional testing phase of our CI/CD pipeline. To activate the functional testing stage, this file should reside at the root level of each repository.

## Command Probe Tests

```yaml
command_tests:
```

- **command_tests**: List of tests to be executed within Docker containers.

  - **name** (Optional): 
    - Description: A descriptive name for the test.
  
  - **description** (Optional): 
    - Description: Context or a brief about the test.
  
  - **commands**: 
    - Description: List of commands to be executed within the container.
      - **command** (Required): 
        - Description: The actual command to run.
      - **expected_output** (Optional): 
        - Description: The expected output of the command.
      - **timeout_seconds** (Optional, Default: 30 seconds): 
        - Description: Time duration before the command is considered timed out.

## Kubernetes Test

```yaml
kubernetes_test:
```

- **env** (Optional): 
  - Description: Environment variables for the container. 
    - **name**: Name of the variable.
    - **value**: Value for the variable.

- **livenessProbe** (Optional): 
  - Description: Specifies the container's health check.
    - Various fields based on Kubernetes liveness probes.

- **readinessProbe** (Optional): 
  - Description: Specifies when the container is ready to serve requests.
    - Various fields based on Kubernetes readiness probes.

- **command** (Optional):
  - Command to run as soon as the pod is started 
    - All fields under command section in k8s pod manifest 

- **args** (Optional):
  - Provide additional arguments to the command
    - All fields under command section in k8s pod manifest 

- **ports** (Optional):
  - Define port for the container which will expose the ports to the outside world 
    ```yaml
    - name
      containerPort
      hostPort 
      protocol 
      hostIP
      ```

- **resources** (Optional): 
  - Description: Resource requests and limits for the container.
    - **requests**: 
      - **memory**: Memory request (e.g., "64Mi").
      - **cpu**: CPU request (e.g., "250m").
    - **limits**: 
      - **memory**: Memory limit (e.g., "128Mi").
      - **cpu**: CPU limit (e.g., "500m").

## Example testing_manifest.yaml template
```yaml
command_tests:
  - name: Descriptive name for this test #Optional field
    description: Description for the test #Optional field
    commands: 
      - command: command to run within the container #Required field
        expected_output: what is the expected stdout of the command above #Optional field
        timeout_seconds: How long a command should take in seconds #Optional field if not set the default value is 30 seconds
      - command: second command to run within the same  container #Optional
        expected_output: expected output of the second command #Optional
        timeout_seconds: How long a command should take in seconds #Optional field if not set the default value is 30 seconds
# Can have multiple commands.
  - name: Descriptive name for this second test#Optional field
    description: Description for the test #Optional field
    commands: 
      - command: command to run within the container #Required field
        expected_output: what is the expected stdout of the command above #Optional field
        timeout_seconds: How long a command should take in seconds #Optional field if not set the default value is 30 seconds
      - command: second command to run within the same  container #Optional
        expected_output: expected output of the second command #Optional
        timeout_seconds: How long a command should take in seconds #Optional field if not set the default value is 30 seconds

kubernetes_test:
  # Optional - will follow the spec of env from podSpec. Need to be relevant for the image being tested
  env: 
    - name: TEST
      value: "test"
    - name: ANOTHERTEST
      value: "anothertest"
    - name: CLUSTER
      value: "epona"
  # Optional - will follow the spec of livenessProbe from podSpec. Need to be relevant for the image being tested
  livenessProbe:
    tcpSocket:
      port: 5432
    initialDelaySeconds: 30
    periodSeconds: 10
  # Optional - will follow the spec of readinessProbe from podSpec. Need to be relevant for the image being tested
  readinessProbe:
    exec:
      command:
      - sh
      - -c
      - exec pg_isready --host=localhost
    initialDelaySeconds: 5
    timeoutSeconds: 1
    periodSeconds: 5
    failureThreshold: 3
  # Optional - will follow the spec of resources from podSpec. Need to be relevant for the image being tested. If this is not set, the default value for the resource spec will be set. Cannot be more than 2Gi memory and 1 CPU
  resources:
    requests:
      memory: "64Mi"
      cpu: "250m"
    limits:
      memory: "128Mi"
      cpu: "500m"

  ports:
    - name: http
      containerPort: 8800
      protocol: TCP 

  command: ["/this/is/mytest.sh"]

  args: ["--port", "8800"]

```