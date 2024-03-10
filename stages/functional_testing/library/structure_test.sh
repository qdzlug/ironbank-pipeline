#!/bin/bash

CST_BINARY="/tmp/container-structure-test"

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

if [[ -f "/tmp/structure.yaml" ]]; then
    print_header "Running Container Structure Test"
    $CST_BINARY test --image "$(cat /tmp/image)" --config "/tmp/structure.yaml" --output junit --test-report /tmp/report.xml || true
else
    # Create a dummy JUnit report indicating no structure tests were defined
    cat <<EOF > /tmp/report.xml
<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="Container Structure Test" tests="1" errors="0" failures="0" skip="0">
    <testcase classname="structureTest" name="No Structure Test Present">
      <skipped message="No structure_test is defined in testing_manifest.yaml"/>
    </testcase>
  </testsuite>
</testsuites>
EOF
    print_yellow "No structure tests found in testing_manifest.yaml." | tee /home/ci/job.log
fi
