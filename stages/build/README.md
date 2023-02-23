# build stage

The `build` stage builds the hardened container image using any artifacts that were added in the `import artifacts` stage. The `build` stage occurs on an isolated GitLab Runner which utilizes an egress policy preventing any external calls to the internet. As a result, you cannot utilize any artifacts in the build which were not provided in the `import artifacts` stage or any packages which are not included on the Container Hardening satellite server.

The project Dockerfile must use an Iron Bank approved base image in building the hardened container image. This can be in the form of one of the UBI base images (UBI7, UBI8) or another image which has been approved and published (ex. - python36, nodejs, etc.). The following is an example of the proper way to reference one of these base images in the `Dockerfile`:

```
ARG REGISTRY_BASE_IMAGE_URL=registry1.dsop.io/ironbank
ARG BASE_IMAGE=redhat/ubi/ubi8
ARG BASE_TAG=8.2

FROM ${REGISTRY_BASE_IMAGE_URL}/${BASE_IMAGE}:${BASE_TAG}
```

### Notes

- When referencing an external resource from the `hardening_manifest.yaml` file in the `import artifacts` stage in the `Dockerfile` build, the filename of the resource must match up exactly with the reference to it in the `Dockerfile`. For example, if the downloaded resource's filename in `hardening_manifest.yaml` is `tar1.tar`, the associated `Dockerfile` command would be `COPY tar1.tar /`.
- The above applies to images retrieved in the `import artifacts` stage as well. The `tag` for the image provided in `hardening_mainfest.yaml` must match the reference to it in the `Dockerfile`. For example, when retrieving the Istio Operator image from Docker Hub, the tag might be `"istio/operator:1.7.3"`. The reference in the `Dockerfile` would then be `FROM istio/operator:1.7.3`. Do not provide the url to the public location where the image resides because the pipeline will not retrieve it.

### Common Issues

##### It says that the file I am copying in the Dockerfile is not found in a failing build stage.

Ensure that the filename referenced in the Dockerfile matches the `filename` of corresponding `resources` entry in `hardening_manifest.yaml`.

##### I am getting an error message that the pipeline is unable to retrieve the image I have provided.

Ensure that the `tag` of the corresponding `resources` entry in `hardening_manifest.yaml` matches the reference to it in the `Dockerfile`. Ensure that the `tag` provided does not utilize a link/public container location. Provide the image `tag` in the following format to ensure things work correctly: `image_name:version`.

##### The build stage is failing because I am unable to retrieve a package.

There are some packages which are not supported on the satellite server. The satellite server consists of RHEL packages. Other package types (python pip modules, ruby gems, npm packages) are not available during the build unless they are provided in the `resources` of the `hardening_manifest.yaml` file. Ensure that any non-RHEL packages are included in the `hardening_manifest.yaml` file in order to utilize them during the container build.
