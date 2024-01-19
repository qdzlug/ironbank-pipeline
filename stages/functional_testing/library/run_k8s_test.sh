#!/bin/bash

# Variables
# NAMESPACE="gitlab-runner-dsop"
UNIQUE_POD_NAME="test-pod-$(uuidgen | cut -c1-8)"

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
print_header "Starting Deployment Script"

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

# print_header "Tailing on the pod events"
# DURATION=90
# INTERVAL=10
# end=$((SECONDS+DURATION))

# while [ $SECONDS -lt $end ]; do
#     kubectl get events -n $NAMESPACE --field-selector involvedObject.name=$UNIQUE_POD_NAME --sort-by=.metadata.creationTimestamp --watch-only
#     sleep $INTERVAL
# done

# Fetch and print pod events
print_header "Describing Pod"
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
    echo $(kubectl get pod $UNIQUE_POD_NAME -n $NAMESPACE -o=jsonpath='{.status.containerStatuses[0].state}')
    
    print_cyan "Check the pod events and logs for more details."
    print_red "Failing ...."
    exit 1
else 
    print_cyan "Current Pod Status: $POD_STATUS"
fi

# Cleanup at the end
print_header "Cleaning Up"
print_yellow "Deleting pod '$UNIQUE_POD_NAME'..."
kubectl delete -f /tmp/podmanifest.yaml -n $NAMESPACE

print_header "Deployment Script Completed"





# Check the final status of the pod
# if [[ "$POD_STATUS" != "Running" && "$POD_STATUS" != "Completed" ]]; then
#     print_red "Error: Pod did not reach the 'Running' or 'Completed' state. Check logs for more details."
#     exit 1
# else
#     print_green "Test passed! Pod reached the desired state."
#     exit 0
# fi