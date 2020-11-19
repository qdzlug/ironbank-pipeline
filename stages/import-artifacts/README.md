# import artifacts stage

This stage will run if the `hardening_manifest.yaml` in the project repository contains any `resources`. The downloader script will not download any files if there are no `resources` listed. The purpose of the `resources` section of the `hardening_manifest.yaml` file is to pull in any external resources for use in the container build. These resources can include, but are not limited to:

- Docker images (such as Docker Hub, Google Container Registry, quay.io)
- RPM/package files (from open source projects, RHEL RPMs, CentOS, etc. for example)
- tarballs (from Amazon S3, open source project pages, company project pages, etc.)

An example of a properly formatted `hardening_manifest.yaml` file's `resources` section with a variety of external resource types is shown below:

```
resources:
  - url: "https://s3.amazonaws.com/ops-manager-kubernetes-build/releases/mongodb-enterprise-operator-binaries-release-1.4.2.tar.gz"
    filename: "mongodb-files1.tar.gz"
    validation:
      type: "sha256"
      value: "3d6b4cfca92067edd5c860c212ff5153d1e162b8791408bc671900309eb555ec"
  - url: https://download.postgresql.org/pub/repos/yum/12/redhat/rhel-8.2-x86_64/postgresql12-contrib-12.3-1PGDG.rhel8.x86_64.rpm
    filename: "postgresql12-contrib-12.3-1PGDG.rhel8.x86_64.rpm"
    validation:
      type: "sha256"
      value: "6CBE0B6E25C46D894B29D9393E79E23B6EB2824A4BA019D1AF6945DAC25ECC68"
  - url: "docker://docker.io/istio/operator@sha256:7af9cf4c7ff7dc66f469bc1b230772c229d3de7e8f160f826f59b495bbc309db"
    tag: "istio/operator:1.6.12"
  - url: "https://example.url.com/requires-authentication-credentials/example-file.ext"
    filename: "example-file.ext"
    validation:
      type: sha256
      value: 87ce779576a0bccf41bcee68814a42865ccf24f12705af69635d6e099d6396mb
    auth:
      type: "basic"
      id: "example-credential"
```

### Notes

- "docker://" must be appended when attempting to pull an image (ex. - `docker://docker.io/istio/operator@sha256:7af9cf4c7ff7dc66f469bc1b230772c229d3de7e8f160f826f59b495bbc309db` or `"docker://gcr.io/distroless/base-debian10@sha256:f4a1b1083db512748a305a32ede1d517336c8b5bead1c06c6eac2d40dcaab6ad"`). The sha256 of the particular image you are attempting to pull must be included as well.
- If any of the external resources require authentication, work with a member of the Iron Bank pipelines team in order to get the necessary credentials added to the project's CI/CD variables.
- Ensure that the `filename` and/or `tag` of the external resource matches the reference in the project's `Dockerfile` to that resource. Otherwise, the build will not work properly because the external resource or image will not have a name which matches in the `Dockerfile`.
