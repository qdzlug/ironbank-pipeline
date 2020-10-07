#!/bin/bash
#set -Eeuo pipefail
set -x
export BASE_BUCKET_DIRECTORY="container-scan-reports"
REMOTE_REPORT_DIRECTORY="$(date +%FT%T)_${CI_COMMIT_SHA}"
export REMOTE_REPORT_DIRECTORY
export S3_HTML_LINK="${S3_REPORT_BUCKET}/${BASE_BUCKET_DIRECTORY}/${CI_PROJECT_NAME}/${IMG_VERSION}/${REMOTE_REPORT_DIRECTORY}"
IM_NAME=$(echo "${CI_PROJECT_PATH}" | sed -e 's/.*dsop\/\(.*\)/\1/')
export IM_NAME
#pip3 install --upgrade pip setuptools wheel pandas mysql mysql-connector-python minepy python-gitlab
# python3 "${PIPELINE_REPO_DIR}/stages/vat/get_parent_info.py" --image "${CI_PROJECT_PATH}" --tag "${IMG_VERSION}" \
#   --glkey "${PYTHON_GL_KEY}" --wlbranch "${WL_TARGET_BRANCH}" --output 'environment.sh'
# source environment.sh
# cat environment.sh
echo "${CI_PROJECT_DIR}" | grep -e 'pipeline-test-project';
if [[ $? = 0 ]]; then
    echo "Skipping vat. Cannot push to VAT when working with pipeline test projects..." ;
fi
else
    echo "would be python script"
fi