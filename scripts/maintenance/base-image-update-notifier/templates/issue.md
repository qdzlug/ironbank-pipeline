## Summary

Base image update available for {{ image }}.

If your project's base image is redhat/ubi/ubi8, please update it to use version 8.6. A recent upstream release has caused an issue with 8.5 images, preventing them from running `dnf update` or `dnf upgrade`, resulting in broken pipelines.

If this image is a dependency for another other images, after it is merged to master all dependent images will also need to be rebuilt or wait for our nightly, automated rebuild and rescan.

## Tasks

- [ ] Update the ARGS (BASE_IMAGE, BASE_TAG) in hardening_manifest.yaml
- [ ] Update the ARGS (BASE_IMAGE, BASE_TAG) in Dockerfile
- [ ] Review findings and justifications
- [ ] Label issue with `Hardening::Review`

> Note: If the above review process is rejected for any reason, the `Hardening::Review` label will be removed and the issue will be sent back to `Open`. Any comments will be listed in this issue for you to address. Once they have been addressed, you **must** re-add the `Hardening::Review` label.

## Questions?

Contact the Iron Bank team by commenting on this issue with your questions or concerns. If you do not receive a response, add `/cc @ironbank-notifications/onboarding`.

Additionally, Iron Bank hosts an [AMA](https://www.zoomgov.com/meeting/register/vJIsf-ytpz8qHSN_JW8Hl9Qf0AZZXSCSmfo) working session every Wednesday from 1630-1730EST to answer questions.

/label ~"Container::Update"
/due in 3 days
