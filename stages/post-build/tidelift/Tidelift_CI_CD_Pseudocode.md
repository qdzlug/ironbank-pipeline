# Tidelift Iron Bank (IB) CI/CD Pipeline Integration Pseudocode 


### Iron Bank CI/CD Gitlab Environment Variables for Tidelift Integration

```
variables:
TIDELIFT_API_KEY: "${TIDELIFT_API_KEY}"
SBOM_DIR: "${ARTIFACT_STORAGE}/sbom"
TIDELIFT_DIR: "${ARTIFACT_STORAGE}/tidelift"
TIDELIFT_ORG_NAME: us-ironbank
TIDELIFT_PROJECT_BRANCH: "${CI_COMMIT_BRANCH}"
#set IB Tier Group to "General" as default for now. 
IRONBANK_CLASSIFICATION: General  
TIDELIFT_PROJECT_GROUP: "${IRONBANK_CLASSIFICATION}" 
TIDELIFT_PROJECT_EXTERNAL_ID: "${IMAGE_NAME}-${IMAGE_TAG}-${CI_COMMIT_REF_NAME}"
 SupplierName/SubGroup/projectname/tagnumber/branch/
#parse the supplier name from "${IMAGE_NAME}" string 
TIDELIFT_PROJECT_SUPPLIER:  "${IMAGE_NAME}" 
TIDELIFT_PROJECT_SUPPLIERTYPE: "${IMAGE-TAG}"
TIDELIFT_PROJECT_NAME: "${TIDELIFT_IMAGE_NAME}-${IMAGE_TAG}-${CI_COMMIT_BRANCH}"  
#notes: "${TIDELIFT_IMAGE_NAME}" uses "${CI_PROJECT_NAME}"
TIDELIFT_CATALOG_NAME: "${TIDELIFT_PROJECT_SUPPLIER}"
#notes ref: https://docs.gitlab.com/ee/ci/variables/predefined_variables.html 
#Variables for Tidelift Reports
TIDELIFT_ALIGNMENT_ID:  TBD
TIDELIFT_CVE_REPORT_ID: TBD
TIDELIFT_CVE_REPORT_NAME:  "${TIDELIFT_PROJECT_EXTERNAL_ID}_tidelift_cve_report.json"
```

## High-level Pseudocode Integration
For each Iron Bank Container Image, Tidelift will process the produced artifact SBOM file for Tidelift alignment for each Pull Requests (PR) and all git branches. 

###Tidelift Project Group Classification

```
#Create the Tidelift Project group based on IB Classification

./tidelift groups new $TIDELIFT_PROJECT_GROUP --organization TIDELIFT_ORG_NAME
   
   Notes: Create the new group, Success! Your group 'general' has been created with the slug 'project-group-name' will be shared 
    		The best approach would be to create a catalog instead of checking for existing group names. Ignore - Error: that group already exists.   
```

###Tidelift Project Alignment with IB SBOM file
To avoid project name race condition in the Tidelift catalog, we recommend for organziations to execute a project alignment instead of checking for existing project names in the database. By default the Tidelift alignment should return success or a fail message, and the job should continue to execute the subsequence tasks. 

**Execute Tidelift Alignment with IB Container Image SBOM**

**if .tidelift project new**

	//run the tidelight alignment for new project and wait for completion
	//capture the response message to determine existing project or new
	//TIDELIFT_ALIGNMENT_ID = Revision: ID

**else** 

	//project exists already 
	./tidelift alignment save --directory . $SBOM_OUTPUT --project $TIDELIFT_PROJECT_NAME 
	//wait for completion
	//TIDELIFT_ALIGNMENT_ID = Revision: ID
	
	

**Example script:**

```
- echo "==========================="
- echo "Align project with Tidelift"
- echo "==========================="
- echo "*****Checking to see if $TIDELIFT_PROJECT_NAME exists in Tidelift."
- |
      if ./tidelift projects new $TIDELIFT_PROJECT_NAME --organization $TIDELIFT_ORG_NAME --default-branch $TIDELIFT_PROJECT_BRANCH --catalog $TIDELIFT_CATALOG_NAME --group $TIDELIFT_PROJECT_GROUP --external-identifier $TIDELIFT_PROJECT_EXTERNAL_ID --force; then
        echo "*****$TIDELIFT_PROJECT_NAME does't exist in tidelift. Aligning project in tidelift for the first time.";
        ./tidelift alignment save --directory . $SBOM_DIR cyclondedx.json --organization $TIDELIFT_ORG_NAME --project $TIDELIFT_PROJECT_NAME --branch $TIDELIFT_PROJECT_BRANCH --wait 
      else 
        echo "*****$TIDELIFT_PROJECT_NAME already exists in tidelift. Skipping tidelift init.";
        echo "*****Attempting to save project:$TIDELIFT_PROJECT_NAME, organization:$TIDELIFT_ORG_NAME, branch:$TIDELIFT_CURRENT_BRANCH"
        ./tidelift alignment save --directory . $SBOM_OUTPUT --project $TIDELIFT_PROJECT_NAME --organization $TIDELIFT_ORG_NAME --branch $TIDELIFT_CURRENT_BRANCH --wait 
      fi
```

### Project Vulnerability Report
After the project alignment is completed, the job should will generate a Vulnerability Report for the open source library packages discovered in the SBOM file. After the job will request the Vulnerability report to be saved in the Iron Bank `SBOM_DIR` directory path as `tidelift_cve_report.json`. 


Process Vulnerability Report 

Verify the Tidelift Alignment Was Successful then generate and capture vulnerability report for the project

**if (tidelift status --revision $TIDELIFT_ALIGNMENT_ID) check for Status: success**

```
generate vulnerability report w/Tidelift API
cature curl request response

wait until the project has been generated 
request vulnerability report 
save vulnerability report Iron Bank `SBOM_DIR`
```


**else**

```echo "unable to process project vulnerability report, project alignment failed.  See log file." ```


**Example script:**

```
 - echo "========================="
    - echo "Report Generation"
    - echo "========================="
    - |
      make_request() {
        curl_output=$(curl -s -H "Accept: application/json" -H "Authorization: $TIDELIFT_API_KEY" \
        -X GET "https://api.tidelift.com/external-api/v1/$TIDELIFT_ORG_NAME/reports/bom_vulnerabilities/status?report_id=$TIDELIFT_CVE_REPORT_ID")
        echo "$curl_output"
      }

    - echo "========================="
    - echo "Report Retrieval"
    - echo "========================="
    - | 
        TIDELIFT_CVE_REPORT_ID=$(curl -s -H "Accept: application/json" -H "Authorization: $TIDELIFT_API_KEY" \
         -X POST "https://api.tidelift.com/external-api/v1/$TIDELIFT_ORG_NAME/reports/bom_vulnerabilities/generate?projects[]=$TIDELIFT_PROJECT_NAME" | jq -r '. report_id')
    - response=$(make_request)
    - response_status=$(echo "$response" | jq -r '.status')
    - |
        TIMEOUT_COUNT=0
        while [ "$response_status" != "completed" ] || [ $TIMEOUT_COUNT -eq 12 ]
        do
            echo "Status is $response_status. Waiting for completion..."
            sleep 5
            response=$(make_request)
            response_status=$(echo "$response" | jq -r '.status')
            TIMEOUT_COUNT=TIMEOUT_COUNT+1;
        done
    - echo "Task completed. Report ID; $(echo "$response" | jq -r '.report_id')"
    - | 
        curl -s -H "Accept: application/json" -H "Authorization: $TIDELIFT_API_KEY" \
         -X GET "https://api.tidelift.com/external-api/v1/$TIDELIFT_ORG_NAME/reports/bom_vulnerabilities?report_id=$TIDELIFT_CVE_REPORT_ID" -o tidelift_cve_report.json
```