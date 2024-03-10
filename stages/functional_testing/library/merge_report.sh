#!/bin/bash

K8S_RESULTS="/tmp/kubernetes-test-results.xml"
CST_RESULTS="/tmp/report.xml"
MERGED_RESULTS="report.xml"  # Final output file

# Check if the Kubernetes test results exist
if [[ -f "$K8S_RESULTS" ]]; then
    echo "<testsuites>" > $MERGED_RESULTS
    grep -v "<?xml" "$K8S_RESULTS" | grep -v "</\?testsuites" >> $MERGED_RESULTS
    grep -v "<?xml" "$CST_RESULTS" | grep -v "</\?testsuites" >> $MERGED_RESULTS
    echo "</testsuites>" >> $MERGED_RESULTS
else
    mv "$CST_RESULTS" $MERGED_RESULTS
fi
