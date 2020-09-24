#!/bin/bash

export repo_name="${IM_NAME}" 
export approval_status="${IMAGE_APPROVAL_STATUS}" 
export public_key="${GPG_PUB_KEY}" 
export image_sha="${IMAGE_ID}" 
export image_name="${CI_PROJECT_NAME}" 
export image_tag="${IMG_VERSION}" 
export image_path="${REGISTRY_URL}/${IM_NAME}:${IMG_VERSION}" 
export image_url="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${IMAGE_FILE}.tar" 
export build_number="${CI_PIPELINE_ID}" 
export image_manifest="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/manifest.json" 
export manifest_name="manifest.json" 
export pgp_signature="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${SIG_FILE}.sig" 
export signature_name="${SIG_FILE}.sig" 
export version_documentation="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${DOCUMENTATION_FILENAME}.json" 
export tar_location="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${REPORT_TAR_NAME}" 
export tar_name="${IMAGE_FILE}.tar" 
export openscap_compliance_results="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/oscap.csv" 
export openscap_oval_results="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/oval.csv" 
export twistlock_results="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/tl.csv" 
export anchore_gates_results="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/anchore_gates.csv" 
export anchore_security_results="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/anchore_security.csv" 
export summary_report="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/summary.csv" 
export full_report="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/all_scans.xlsx" 
export openscap_report="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/openscap/report.html" 
export oval_report="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/openscap/report-cve.html" 
export signature_name="${SIG_FILE}.sig" 
export output_dir="${ARTIFACT_DIR}" 
export project_license="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${PROJECT_LICENSE}"
export project_readme="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${PROJECT_README}"
