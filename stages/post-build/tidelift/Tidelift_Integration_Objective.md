# Tidelift Iron Bank CI/CD Pipeline Integration Objective 


## CI/CD Integration Description
Iron Bank is the DoD's source for hardened containers. A hardened container allows the application/container to run on an ATO'd Kubernetes cluster that meets the DevSecOps Reference Design. 

**Continuous Accreditation of Hardened Images | High-Level CI/CD Pipeline Workflow**

![Continuous Accreditation of Hardened Images | CI/CD Pipeline Workflow](https://p1.dso.mil/IBVS_pipeline.e027a745.webp "Optional Title")
[https://p1.dso.mil/IBVS_pipeline.e027a745.webp](https://p1.dso.mil/IBVS_pipeline.e027a745.webp)

The CI/CD Pipeline Workflow high-level stages:

1. Initialization 
2. Antivirus Scan
3. Build
	* 3.5. Post-Build
4. Scanning
5. Check CVEs
6. Publish (Registry 1)

Containers submitted to Iron Bank will be scanned and evaluated according to **Iron Bank Acceptance Baseline Criteria (ABC)** and judged complaint or non-compliant. Each container will also receive an **Overall Risk Assement (ORA) score**.

## Objective 
Tidelift will integrate in the existing Iron Bank CI/CD Pipeline Workflow following the **Build Stage** of the container hardening proces described above. More specifically during `post-build` stage composed of two major jobs: 1) `create-sbom` job which generates the SBOM artifacts and 2) `tidelift-upload` job that will use the Tidelift CLI binary to authenticate and upload the container image SBOM (Cyclonedx and/or SPDX) file into the Tidelift SaaS.
After completing the SBOM upload (Tidelift alignment), a Vulnerability report will be generated and requested from Tidelift to be uploaded into the Iron Bank Registry 1 services.  

![image info](tidelift_upload.png)

All Gitlab errors during the Tidelift SBOM upload and API vulnerability report request will be logged, but the Gitlab pipeline will continue to run and execute the subsequent stages and jobs in the IB CI/CD workflow process. One key concern to address will be the `tidelift-upload` job time to completion, which may delay the subsequent stages and jobs in the pipeline.  
 
Once the conctainer image SBOM is processed by Tidelift, the Iron Bank teams (VAT, CHT Cybersecurity, and Pop-team) will be able to use the Tidelift APIs to capture open source library components/package data intelligence related to the Security, Mantenance, Licensing, Software Development Best Practices/Standards (NIST SSDF, and Linux Foundation OpenSSF Scorecard Checks). 



#Iron Bank Varibale Mapping from Repo1, Registry1, IB Catalog, and VAT
A project naming convention has been established with Iron Bank and Tidelift for project referencing and alignment. The Iron Bank catalog services such as Repo1, Registry1, IB Catalog, and VAT, all have different information architecture for the projects. As a result, to normalize the supplier name, project type (group), project name, branch name, with Iron Bank and Tidelift have agreed on the following mapping:

* Tidelift Catalog Name: by Supplier Name (ie. Red Hat)
* Tidelift Project Name: project-name+tagnumber+branch-name 
* Tidelift External Prj Identifier: SupplierName/SubGroup/projectname/tagnumber/
* Tidelift Default branch: gitlab project branch name
* Tidelift Group: Iron Bank Core, default to "general"

### Gitlab Variables 

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


#Iron Bank Staging Pipeline Environment 
To Test the CI/CD gitlab integration script, Iron Bank is providing access to the Staging Pipeline envornment. 
[https://code-ib-zelda.staging.dso.mil/ironbank-tools/ironbank-pipeline](https://code-ib-zelda.staging.dso.mil/ironbank-tools/ironbank-pipeline)

Proper credentials have to be granted from the IB Pops team to access the **Staging CI/CD pipeline** environment. A standard DoD Common Access Card (CAC) can be used for authentication. However, IB has presented an alternative option for Tidelift to use the Appgate SDP desktop client with proper [https://login.dso.mil](https://login.dso.mil) credentials to access the Staging Iron Bank Pipeline. 

Once authenticated to the Staging CI/CD pipeline environment, Tidelift will be able to directly contibue to the gitlab script programming. The `tidelift-upload` job will handle the project mapping, Tidelift catalog group creation, and Tidelift CLI alignment (SBOM upload process). 
 
 
