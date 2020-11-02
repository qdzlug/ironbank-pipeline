# scan-artifacts

The `scan-artifacts` stage is run in the event there are external resources required for the container build. These external resources are obtained in the `import artifacts` stage. `scan-artifacts` utilizes ClamAV antivirus and malware scanning in order to detect the presence of infected files. It is a security measure implemented to ensure there are no malicious programs/pieces of code which are included in the final hardened container.

This stage runs `freshclam` in order to retrieve the most up-to-date virus and malware information and populate the ClamAV database before scanning. Then, `clamscan` is run on the external resources retrieved in the `import artifacts` stage. This scan works on images as well - for example, if a container build utilizes a public Docker image, it will scan the image after it is saved as a tar file.

`scan-artifacts` will automatically fail in the event there is an infected file found. If the finding is deemed to be a false positive, contributors must work with the Iron Bank Container Hardening/pipelines team in order to have the finding whitelisted. Contributors will be responsible for proving that the infected file is in fact a false positive.
