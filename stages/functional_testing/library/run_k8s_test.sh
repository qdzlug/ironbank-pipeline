#!/bin/bash

# Variables
# NAMESPACE="gitlab-runner-dsop"
UNIQUE_POD_NAME="test-pod-$(uuidgen | cut -c1-8)"

JUNIT_OUTPUT="kubernetes-test-results.xml"
echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" > $JUNIT_OUTPUT
echo "<testsuites>" >> $JUNIT_OUTPUT

# Functions
print_header() {
    echo -e "\n\n\033[1;33m-----------------------------------------"
    echo -e "$1"
    echo -e "-----------------------------------------\033[0m\n"
}

print_green() {
    echo -e "\033[1;32m$1\033[0m"
}

print_red() {
    echo -e "\033[1;31m$1\033[0m"
}

print_blue() {
    echo -e "\033[1;34m$1\033[0m"
}

print_yellow() {
    echo -e "\033[1;33m$1\033[0m"
}

print_cyan() {
    echo -e "\033[1;36m$1\033[0m"
}

# Script Start
print_header "Running Kubernetes Test. Starting Deployment Script"

# Ensure the testing namespace exists
print_green "Trusting namespace '$NAMESPACE' exists..."
# kubectl create namespace $NAMESPACE || print_yellow "Namespace '$NAMESPACE' already exists."

# Extract image from the pod manifest
IMAGE_FROM_MANIFEST=$(awk '/image:/ {print $2}' /tmp/podmanifest.yaml)

print_header "Deploying Pod"
print_green "Creating the '$UNIQUE_POD_NAME' pod with the image '$IMAGE_FROM_MANIFEST'..."
sed -i "s/name: test-pod/name: $UNIQUE_POD_NAME/" /tmp/podmanifest.yaml
kubectl apply -f /tmp/podmanifest.yaml -n $NAMESPACE

# Monitor the status of the pod for 3 minutes
print_green "Monitoring pod status for 3 minutes..."
FAILURE_COUNTER=0
RUNNING_COUNTER=0

for i in {1..18}; do  # 18 iterations * 10 seconds = 3 minutes total
    POD_STATUS=$(kubectl get pod $UNIQUE_POD_NAME -n $NAMESPACE --no-headers | awk '{print $3}')
    echo $(kubectl get pod $UNIQUE_POD_NAME -n $NAMESPACE)
    echo $POD_STATUS
    
    if [[ "$POD_STATUS" == "Running" ]]; then
        RUNNING_COUNTER=$((RUNNING_COUNTER + 1))
        print_green "Pod is running! Count: $RUNNING_COUNTER"
        if [[ $RUNNING_COUNTER -ge 3 ]]; then
            print_green "Pod has been running consecutively for 3 times. Exiting..."
            break
        fi
        FAILURE_COUNTER=0  # Reset the failure counter if the pod is running
    elif [[ "$POD_STATUS" == "CrashLoopBackOff" || "$POD_STATUS" == "Error" || "$POD_STATUS" == "Failed" || "$POD_STATUS" == "Pending" ]]; then
        FAILURE_COUNTER=$((FAILURE_COUNTER + 1))
        RUNNING_COUNTER=0  # Reset the running counter if the pod is not running
        if [[ $FAILURE_COUNTER -ge 4 ]]; then
            print_red "Pod has been in a failure state consecutively for 4 times. Exiting..."
            break
        fi
    else
        # Reset both counters for other statuses
        FAILURE_COUNTER=0
        RUNNING_COUNTER=0
    fi
    sleep 10
done

# Find out the time to sleep to get the final pod events using describe 
initialDelaySeconds=0
if grep -q "initialDelaySeconds" testing_manifest.yaml; then
    initialDelaySeconds=$(grep "initialDelaySeconds" testing_manifest.yaml | awk '{print $2}' | head -n 1)
fi
# Fetch and print pod events
print_header "Describing Pod"
print_cyan "Waiting for $initialDelaySeconds seconds to get the final pod events..."
sleep $initialDelaySeconds
echo "$(kubectl describe pod $UNIQUE_POD_NAME -n $NAMESPACE)"

# Fetch logs of the pod if it's up
print_header "Fetching Pod Logs"
# Fetch logs of the pod if it's up
POD_LOGS=$(kubectl logs $UNIQUE_POD_NAME -n $NAMESPACE)
if [[ -z "$POD_LOGS" ]]; then
    print_red "Logs for $UNIQUE_POD_NAME are empty. Status of the pod is $POD_STATUS"
else
    print_blue "$POD_LOGS"
fi

# Fetch and print pod events
POD_DESCRIBE=$(kubectl describe pod $UNIQUE_POD_NAME -n $NAMESPACE)
# echo "$POD_DESCRIBE"

# Check if the pod is not running and exit with an error
print_header "Final Pod Status Check"
if [[ "$POD_STATUS" != "Running" && "$POD_STATUS" != "Completed" ]]; then
    print_red "Error: Pod did not reach the 'Running' or 'Completed' state within the expected time."
    POD_EVENTS=$(kubectl describe pod $UNIQUE_POD_NAME -n $NAMESPACE | awk '/Events:/{flag=1;next}/^[[:space:]]*$/{flag=0}flag' | tail -n 8)
    FAILURE_REASON=$(kubectl describe pod $UNIQUE_POD_NAME -n $NAMESPACE | grep -oP 'Reason:\s+\K.*')
    CONTAINER_STATUS=$(kubectl get pod $UNIQUE_POD_NAME -n $NAMESPACE -o=jsonpath='{.status.containerStatuses[0].state}')
    echo $CONTAINER_STATUS
    print_red "Reason: $FAILURE_REASON"
    
    print_cyan "Check the pod events and logs for more details."
    print_red "Failing ...."
    # Start testsuite
    echo "<testsuite name='Kubernetes Deployment'>" >> $JUNIT_OUTPUT

    # Include the failure testcase
    echo "<testcase name='Kubernetes Test'>" >> $JUNIT_OUTPUT
    echo "<failure><![CDATA[Pod failed to reach Running or Completed state. \n\nFailure Reason: $FAILURE_REASON, \n\nContainer Status: $CONTAINER_STATUS, \n\nPod Events: $POD_EVENTS, \n\nPod Logs: $POD_LOGS]]></failure>" >> $JUNIT_OUTPUT
    echo "</testcase>" >> $JUNIT_OUTPUT

    # Close testsuite
    echo "</testsuite>" >> $JUNIT_OUTPUT

    echo "</testsuites>" >> $JUNIT_OUTPUT
    exit 1
else 
    print_cyan "Current Pod Status: $POD_STATUS"
    CONTAINER_STATUS=$(kubectl get pod $UNIQUE_POD_NAME -n $NAMESPACE -o=jsonpath='{.status.containerStatuses[0].state}')
    echo $CONTAINER_STATUS
    echo $(kubectl get pod $UNIQUE_POD_NAME -n $NAMESPACE --no-headers)
    echo "<testsuite name='Kubernetes Test'><testcase classname='Kubernetes Test' name='Pod Status Check'><system-out>Pod Status: $POD_STATUS, Container Status: $CONTAINER_STATUS</system-out></testcase></testsuite>" >> $JUNIT_OUTPUT
    echo "</testsuites>" >> $JUNIT_OUTPUT
fi

# Cleanup at the end
print_header "Cleaning Up"
print_yellow "Deleting pod '$UNIQUE_POD_NAME'..."
kubectl delete -f /tmp/podmanifest.yaml -n $NAMESPACE

print_header "Deployment Script Completed"