# Adding a proxy to Nexus

## Description of new proxy

<!-- Provide a description of the proxy that is to be added here -->

## Acceptance Criteria (AC)

<!--- What is the acceptance criteria specific to this proxy issue?
    e.g.
    - [ ] Log for lint job now prints VAT API version with INFO log level
    or
    - [ ] S3 upload no longer includes docker archive
-->

- [ ] New build args, config files, etc. have been added to the pipeline
- [ ] New proxy name has been added to `ACCESS_LOG_REPOS` CI variable
- [ ] Use of new proxy has been documented in DCCSCR repo, along with best practices
<!-- Example of best practices would be pinning package version in  requirements.txt boto3==1.24.4 -->
- [ ] Access log parsing updated to accommodate new proxy

## Definition of Done (DoD)

<!-- Add/remove tasks to demonstrate completeness of issue -->

- [ ] Proxy tested in staging environment
