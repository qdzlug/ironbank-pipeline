#!/bin/bash

###
#
# Executes code copied from the script in the "shellcheck" stage of the
# ironbank pipeline .gitlab-ci.yml. 
#
# Note: The embedded scripts did not scan (jq complained) on the  mac-os 
# where this was tested.
#
###

set -o pipefail
set +e # remove gitlab ci setting
shopt -s nullglob
files=$(echo stages/*/*.sh)
if [ -n "$files" ]
then
  shellcheck --exclude=SC2153 --format=gcc -- $files
  ret=$?
fi
echo "# Scanning embedded scripts..."
ret=0
IFS=$'\n' # Minor bug: newlines in filenames will still be processed incorrectly
for file in $(find . -name '*.yaml' -o  -name '*.yml')
do
  echo "# $file"
  yq -r '.[] | objects | .before_script, .script, .after_script | select(. != null) | join("\n")' "$file" | shellcheck --exclude=SC2153 --format=gcc -s bash -
  yq_ret=$?
  if [ $yq_ret -ne 0 ]
  then
    ret=$yq_ret
  fi
done
exit "$ret"
