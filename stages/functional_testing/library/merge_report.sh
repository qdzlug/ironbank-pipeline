#!/bin/bash

echo "<testsuites>" > report.xml
grep -v "<\?xml" /tmp/report.xml | grep -v "</\?testsuites" >> report.xml
grep -v "<\?xml" /tmp/kubernetes-test-results.xml | grep -v "</\?testsuites" >> report.xml
echo "</testsuites>" >> report.xml