#!/bin/bash

CST_BINARY="/tmp/container-structure-test"

if [[ -f "/tmp/structure.yaml" ]]; then
    print_header "Running Container Structure Test"
    $CST_BINARY test --image "$(cat /tmp/image)" --config "/tmp/structure.yaml" --output junit --test-report /home/ci/report.xml | tee /home/ci/job.log
else
    # Create a dummy JUnit report indicating no structure tests were defined
    cat <<EOF > /home/ci/report.xml
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
