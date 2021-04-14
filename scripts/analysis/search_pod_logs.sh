#!/bin/bash

###
#
# Searches the namespace TARGET_NAMESPACE and identifies all pods
# containing $TARGET_PODNAME in the name. Then extracts the
# contents of $TARGET_LOG_PATH to a timestamped log file.
#
# The default values get the twistlock-defender logs"
#
###

set -euo pipefail

TARGET_NAMESPACE=${TARGET_NAMESPACE:-twistlock}
TARGET_PODNAME=${TARGET_PODNAME:-twistlock-defender}
TARGET_LOG_PATH=${TARGET_LOG_PATH:-var/lib/twistlock/log/defender.log}

logfile="${TARGET_NAMESPACE}_${TARGET_PODNAME}_$(echo "$TARGET_LOG_PATH" |
  awk -F'/' '{print $NF}')_$(date +%F_%H-%M-%S).log"

echo "log file: $logfile"

while read -r line; do
  echo "searching pod $line"
  kubectl exec -n "$TARGET_NAMESPACE" "$line" -- cat "$TARGET_LOG_PATH" >>"$logfile"
done <<<"$(kubectl get pods -n "$TARGET_NAMESPACE" | grep twistlock-defender | awk '{print $1}')"
