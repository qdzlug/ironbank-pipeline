#!/bin/bash
S3_HTML_LINK="https://s3-us-gov-west-1.amazonaws.com/${S3_REPORT_BUCKET}/${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMAGE_VERSION}"
directory_date=$(date --utc '+%FT%T.%3N')
public_key=$(<"${IB_CONTAINER_GPG_PUBKEY}")

export directory_date
export REMOTE_DOCUMENTATION_DIRECTORY="${directory_date}_${CI_PIPELINE_ID}"
export REMOTE_REPORT_DIRECTORY="${REMOTE_DOCUMENTATION_DIRECTORY}/reports"
export repo_name="${IMAGE_NAME}"
export public_key
export image_sha="${IMAGE_ID}"
export image_name="${CI_PROJECT_NAME}"
export image_tag="${IMAGE_VERSION}"
export image_path="${REGISTRY_URL}/${IMAGE_NAME}:${IMAGE_VERSION}"
export build_number="${CI_PIPELINE_ID}"
export image_manifest="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/manifest.json"
export manifest_name="manifest.json"
export version_documentation="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${DOCUMENTATION_FILENAME}.json"
export tar_location="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${REPORT_TAR_NAME}"
export tar_name="${REPORT_TAR_NAME}"
export openscap_compliance_results="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/oscap.csv"
export twistlock_results="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/tl.csv"
export anchore_gates_results="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/anchore_gates.csv"
export anchore_security_results="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/anchore_security.csv"
export summary_report="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/summary.csv"
export full_report="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/all_scans.xlsx"
export openscap_report="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/openscap/report.html"
export output_dir="${ARTIFACT_DIR}"
export project_license="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${PROJECT_LICENSE}"
export project_readme="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${PROJECT_README}"

export SHORTENED_PATH="${IMAGE_PATH}/${IMAGE_VERSION}/${REMOTE_REPORT_DIRECTORY}"
export README_PATH_SHORT="${SHORTENED_PATH}/${PROJECT_README}"
export LICENSE_PATH_SHORT="${SHORTENED_PATH}/${PROJECT_LICENSE}"
export TAR_PATH_SHORT="${SHORTENED_PATH}/${REPORT_TAR_NAME}"
