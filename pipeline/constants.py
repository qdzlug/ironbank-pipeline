import os
import re

# Pull in all relevant environment variables
# Note: not using GET for some that are required, so we want it to fail with KeyError


MANIFEST_FILENAME = "manifest.json"
SIGNATURE_FILENAME = "signature.sig"
DOCUMENTATION_FILENAME = "documentation.json"
OSCAP_CVE_HTML_FILENAME = "report-cve.html"
OSCAP_CVE_XML_FILENAME = "report-cve.xml"
OSCAP_HTML_FILENAME = "report.html"
ANCHORE_GATES_REPORT_FILENAME = "anchore_gates.json"
ANCHORE_SECURITY_REPORT_FILENAME = "anchore_vulns_new.json"
SCAN_METADATA_FILENAME = "scan-metadata.json"
REPORT_DIRECTORY = os.path.abspath('reports')
OSCAP_DIRECTORY = os.path.join(REPORT_DIRECTORY, "openscap")
TWISTLOCK_DIRECTORY = os.path.join(REPORT_DIRECTORY, "twistlock")
ANCHORE_DIRECTORY = os.path.join(REPORT_DIRECTORY, "anchore")
CSV_DIRECTORY = os.path.join(REPORT_DIRECTORY, "csvs")
LATEST_SCANS_FILENAME = "latest-images.json"

S3_AWS_REGION = 'us-gov-west-1'

DCAR_URL = 'https://dcar.dsop.io'

# Agent with connectivity only to internal nexus and satellite
DISCONNECTED_BUILD_AGENT = 'jenkins-prebuild-agent'
# Agent with scanning tools and connectivity to scanning services
SCANNING_AGENT = "jenkins-oscap-agent"
# Agent that needs connectivity to the WWW
WORLD_CONNECTED_AGENT = "jenkins-downloader-agent"
# Agent that needs connevtivity to wherever we are publishing (s3)
PUBLISHING_AGENT = "jenkins-oscap-agent"

# NOTE: This is arguably an evnvironment value. TODO: find a better home
S3_REPORT_BUCKET = 'ironbank-pipeline-artifacts'

# Defining all of the credentialsId values here helps to support IAC by
# creating a clear list of Jenkins environment dependencies.

credentialsId = {
    "JENKINS_API_USERPASS": 'jenkins-api-access',
    "GITLAB_API_TOKEN": 'jenkins-gitlab-api-token',
    "CONTAINER_SIGNING_PUBLIC_KEY": 'IBContainerSigningPublicKey'
}

# Defining stage names here allows us to depend on the stage name value in
# other code such as the ContributorReport routines which only publish logs
# for errors that occur in certain stages.

stage = {
    "BUILD": 'Build',
    "STAGE": 'Stage Artifacts',
    "IMPORT": 'Import Artifacts'
}

CONTRIBUTOR_STAGES = re.compile(f"({stage['BUILD']}|{stage['STAGE']}|{stage['IMPORT']}")

# GITLAB CI CONSTANTS
GITLAB_URL = os.environ.get("CI_SERVER_URL") or "https://repo1.dsop.io"
JOB_ID = os.environ.get("CI_JOB_ID")
PROJECT_NAME = os.environ.get("CI_PROJECT_NAME")
CURRENT_BRANCH = os.environ.get("CI_COMMIT_BRANCH")
REPO_URL = os.environ.get("CI_PROJECT_URL")
LOCK_URL = os.environ.get("CI_REPOSITORY_URL")
