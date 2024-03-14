import os
import re
import sys
import json
import time
import shutil
import tempfile
import datetime
import subprocess
from pathlib import Path

from pipeline.project import DsopProject
from pipeline.hardening_manifest import HardeningManifest
from pipeline.container_tools.skopeo import Skopeo
from pipeline.container_tools.buildah import Buildah
from pipeline.image import Image, ImageFile
from pipeline.utils.decorators import subprocess_error_handler, stack_trace_handler
from common.utils import logger

log = logger.setup("build")


def write_dockerfile_args(dockerfile_args: list["str"]):
    """Overwrite Dockerfile args that are defined in the hardening manifest."""
    with Path("Dockerfile").open(
        mode="r+",
        encoding="utf-8",
    ) as f:
        dockerfile_content = []
        for line in f.readlines():
            dockerfile_content.append(line)
            if re.match(r"^FROM", line):
                dockerfile_content += dockerfile_args
        # replace all file content with updated content
        f.seek(0)
        f.truncate()
        f.writelines(dockerfile_content)


def create_mounts(mount_conf_path: Path, pipeline_build_dir: Path):
    """Mount config files required for use of internal proxy."""
    mounts = []
    if os.environ.get("DISTRO_REPO_DIR"):
        mounts.append(
            pipeline_build_dir
            / f"{os.environ['DISTRO_REPO_DIR']}:{os.environ['DISTRO_REPO_MOUNT']}"
        )
    mounts.append(pipeline_build_dir / "ruby" / ".ironbank-gemrc:.ironbank-gemrc")
    mounts.append(pipeline_build_dir / "ruby" / "bundler-conf:.bundle/config")
    with mount_conf_path.open("a+") as f:
        for mount in mounts:
            f.write(f"{mount}\n")
    return mounts


# resource_type set to file by default so image is explicitly set
# resource_type is not used unless value = image, but it is set to file for clarity of purpose
# TODO: consider passing a true "type" for resource_type (i.e. resource_type = Image or resource_type = Path)
@subprocess_error_handler("Failed to load resources")
def load_resources(
    resource_dir: str, resource_type: str = "file", skopeo: Skopeo = None
):
    """Load resources from a specified directory.

    This function handles both file and image type resources. If the resource
    type is an image and a Skopeo instance is provided, it will use Skopeo
    to copy the image.

    Arguments:
    - resource_dir: The directory where resources are stored.
    - resource_type: (Optional) The type of resources in the directory. Defaults to 'file'.
    - skopeo: (Optional) An instance of the Skopeo class. Required if the resource_type is 'image'.
    """
    for resource_file in os.listdir(resource_dir):
        resource_file_obj = Path(resource_dir, resource_file)
        if resource_file_obj.is_file() and not resource_file_obj.is_symlink():
            if resource_type == "image" and skopeo:
                manifest = subprocess.run(
                    ["tar", "-xf", resource_file_obj.as_posix(), "-O", "manifest.json"],
                    capture_output=True,
                    check=True,
                )
                manifest_json = json.loads(manifest.stdout)
                image_url = manifest_json[0]["RepoTags"][0]
                # These two if statements make sure the arm64 build only gets arm64 tars
                # and the x86 build only gets x86 tars.
                if (
                    os.environ["CI_JOB_NAME"] == "build-arm64"
                    and "arm64" in resource_file_obj.name
                ):
                    log.info("loading arm64 image %s", resource_file_obj)
                    skopeo.copy(
                        ImageFile(
                            file_path=resource_file_obj, transport="docker-archive:"
                        ),
                        Image(url=image_url, transport="containers-storage:"),
                        log_cmd=True,
                    )
                if (
                    os.environ["CI_JOB_NAME"] == "build"
                    and "arm64" not in resource_file_obj.name
                ):
                    log.info("loading image %s", resource_file_obj)
                    skopeo.copy(
                        ImageFile(
                            file_path=resource_file_obj, transport="docker-archive:"
                        ),
                        Image(url=image_url, transport="containers-storage:"),
                        log_cmd=True,
                    )
            else:
                shutil.move(resource_file_obj, Path(resource_file))
        else:
            log.error("Resource type is invalid")
            sys.exit(1)


def get_parent_label(
    skopeo: Skopeo,
    hardening_manifest: HardeningManifest,
    base_registry: str,
):
    """Retrieve parent image digest if base image is defined in hardening
    manifest returns an empty string if one is not defined."""
    if hardening_manifest.base_image_name:
        base_image = Image(
            registry=base_registry,
            name=hardening_manifest.base_image_name,
            tag=hardening_manifest.base_image_tag,
        )
        return f"{base_image}@{skopeo.inspect(base_image.from_image(transport='docker://'), log_cmd=True)['Digest']}"
    # if no base image, return empty string instead of None
    return ""


@subprocess_error_handler("Failed to start squid")
def start_squid(squid_conf: Path):
    """Start squid proxy to create access log file."""
    parse_cmd = ["squid", "-k", "parse", "-f", squid_conf]
    start_cmd = ["squid", "-f", squid_conf]
    for cmd in [parse_cmd, start_cmd]:
        subprocess.run(cmd, check=True)
    # build will fail while squid is starting without this
    time.sleep(5)


def generate_build_env(image_details: dict, image_name: str, image: Image, digest: str):
    """Creates env file to be used later in pipeline."""
    build_envs = [
        f"IMAGE_ID=sha256:{image_details['FromImageID']}\n",
        f"IMAGE_PODMAN_SHA={digest}\n",
        f"IMAGE_FULLTAG={image.from_image(transport='')}\n",
        f"IMAGE_NAME={image_name}\n",
        # using utcnow because we want to use the naive format (i.e. no tz delta of +00:00)
        f"BUILD_DATE={datetime.datetime.utcnow().isoformat(sep='T', timespec='seconds')}Z\n",
    ]
    for env_ in build_envs:
        log.info(env_.strip())
    with Path(f"{os.environ["ARTIFACT_DIR"]}/build.env").open(
        mode="a+",
        encoding="utf-8",
    ) as f:
        f.writelines(build_envs)
    with Path(f"{os.environ['ARTIFACT_DIR']}/build.json").open(
        "w", encoding="utf-8"
    ) as f:
        f.write(json.dumps({
            "IMAGE_ID": f"sha256:{image_details['FromImageID']}",
            "IMAGE_PODMAN_SHA": digest,
            "IMAGE_FULLTAG": image.from_image(transport=''),
            "IMAGE_NAME": image_name,
            "BUILD_DATE": datetime.datetime.utcnow().isoformat(sep='T', timespec='seconds'),
        }))


# decorate main to capture all subprocess errors
@stack_trace_handler
def main():
    """Main method."""
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    staging_image = Image(
        registry=os.environ["REGISTRY_PRE_PUBLISH_URL"],
        name=hardening_manifest.image_name,
        tag=f"ibci-{os.environ['CI_PIPELINE_ID']}-{os.environ['CI_JOB_ID']}",
    )
    base_registry = os.environ["BASE_REGISTRY"]
    artifact_storage_dir = Path(os.environ["ARTIFACT_STORAGE"])
    build_artifact_dir = Path(os.environ["ARTIFACT_DIR"])
    imports_dir = artifact_storage_dir / "import-artifacts"
    image_dir = imports_dir / "images"
    resource_dir = imports_dir / "external-resources"
    pipeline_build_dir = Path(
        os.environ["PIPELINE_REPO_DIR"], "pipeline1", "2-build"
    ).absolute()
    mount_conf_path = Path().home().joinpath(".config", "containers", "mounts.conf")

    build_artifact_dir.mkdir(parents=True, exist_ok=True)

    log.info("Determine source registry based on branch")
    if os.environ.get("STAGING_BASE_IMAGE"):
        base_registry += "-staging"
        prod_auth_path = Path(os.environ["DOCKER_AUTH_FILE_PRE_PUBLISH"])
    else:
        prod_auth_path = Path(os.environ["DOCKER_AUTH_FILE_PULL"])

    staging_auth_path = Path(os.environ["DOCKER_AUTH_FILE_PRE_PUBLISH"])

    buildah = Buildah(authfile=prod_auth_path)
    skopeo = Skopeo()

    # gather files and subpaths
    log.info("Load any images used in Dockerfile build")
    load_resources(resource_dir=image_dir, resource_type="image", skopeo=skopeo)
    # Both an arm64 build and amd64 build will have all the same resources available.
    log.info("Load HTTP and S3 external resources")
    load_resources(resource_dir=resource_dir)

    log.info("Converting labels from hardening manifest into command line args")

    # Create new skopeo instance using prod auth as authfile
    parent_label = get_parent_label(
        skopeo=Skopeo(authfile=prod_auth_path),
        hardening_manifest=hardening_manifest,
        base_registry=base_registry,
    )

    if hardening_manifest.base_image_name:
        log.info("Verifying parent image signature")
        if not os.environ.get("STAGING_BASE_IMAGE"):
            with tempfile.TemporaryDirectory(
                prefix="DOCKER_CONFIG-"
            ) as docker_config_dir:
                shutil.copy(
                    prod_auth_path,
                    Path(docker_config_dir, "config.json"),
                )
                # TODO: Find a workaround for getting Cosign Verify passing with no network
                # if not Cosign.verify(
                #     image=parent_image,
                #     docker_config_dir=docker_config_dir,
                #     use_key=False,
                #     log_cmd=True,
                # ):
                #     log.debug("Failed to verify parent image signature")
                #     log.debug(
                #         "Cosign is unable to initialize properly without network access"
                #     )

    ib_labels = {
        "maintainer": "ironbank@dsop.io",
        # provide time in format YYYY-MM-DD HH:mm:SS+00:00 where +00:00 is the utc delta
        # .now() with tz passed provides an aware object whereas .utcnow() provides a naive object
        "org.opencontainers.image.created": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(sep=" ", timespec="seconds"),
        "org.opencontainers.image.source": os.environ["CI_PROJECT_URL"],
        "org.opencontainers.image.revision": os.environ["CI_COMMIT_SHA"],
        "mil.dso.ironbank.image.parent": parent_label,
        "mil.dso.ironbank.ci.id": os.environ["CI_PIPELINE_ID"],
    }

    log.info("Converting build args from hardening manifest into command line args")
    http_proxies = {
        "http_proxy": "http://localhost:3128",
        "HTTP_PROXY": "http://localhost:3128",
    }

    log.info("Start up the forward proxy")
    start_squid(squid_conf=Path(pipeline_build_dir, "squid.conf"))

    log.info("Adding the ironbank.repo to the container via mount.conf")
    # add mounts to mounts.conf
    create_mounts(
        mount_conf_path=mount_conf_path, pipeline_build_dir=pipeline_build_dir
    )

    # TODO: use the NEXUS_HOST_URL env variable for the values pulled from this file
    with Path(pipeline_build_dir, "build-args.json").open(
        mode="r",
        encoding="utf-8",
    ) as f:
        build_args = json.load(f)
        # create list of lists, with each sublist containing an arg
        # sublist needed for f.writelines() on arg substitution in Dockerfile
        dockerfile_args = ["\n"] + [f"ARG {k}\n" for k in build_args.keys()]

    write_dockerfile_args(dockerfile_args=dockerfile_args)

    # args for buildah's ulimit settings
    buildah_ulimit_args = json.loads(os.environ.get("BUILDAH_ULIMIT_ARGS", "{}")) or {
        "nproc": "2000:2000"
    }

    log.info("Build the image")
    buildah.build(
        context=".",
        build_args={
            **hardening_manifest.args,
            "BASE_REGISTRY": base_registry,
            **http_proxies,
            **build_args,
        },
        labels={
            **ib_labels,
            **hardening_manifest.labels,
        },
        format_="oci",
        log_level="warn",
        default_mounts_file=mount_conf_path,
        storage_driver="vfs",
        ulimit_args=buildah_ulimit_args,
        tag=staging_image,
        log_cmd=True,
    )

    # Instantiate new objects from existing staging image attributes
    src = staging_image.from_image(transport="containers-storage:")
    dest = staging_image.from_image(transport="docker://")

    # TODO: skip the following skopeo copies on local build, maybe change the copy to local dir?
    skopeo.copy(
        src=src,
        dest=dest,
        digestfile=Path(build_artifact_dir, "digest"),
        dest_authfile=staging_auth_path,
        log_cmd=True,
    )

    if (
        os.environ.get("STAGING_BASE_IMAGE")
        or os.environ["CI_COMMIT_BRANCH"] == "development"
    ):
        for tag in hardening_manifest.image_tags:
            dest = dest.from_image(tag=tag)
            skopeo.copy(src, dest, dest_authfile=staging_auth_path, log_cmd=True)

    local_image_details = buildah.inspect(image=src, storage_driver="vfs", log_cmd=True)

    # get digest from skopeo copy digestfile
    with Path(build_artifact_dir, "digest").open(
        mode="r",
        encoding="utf-8",
    ) as f:
        digest = f.read()

    generate_build_env(
        image_details=local_image_details,
        image_name=hardening_manifest.image_name,
        image=src,
        digest=digest,
    )

    log.info("Archive the proxy access log")
    access_log = Path("access.log")
    # - requires octal format of 644 to convert to decimal
    #   functionally equivalent to int('644', base=8)
    # - We receive "follow_symlinks is unavailable on this platform" if follow_symlinks flag is passed to chmod.
    #   Should we check for symlinks, even though we are creating this file?
    access_log.chmod(0o644)
    shutil.copy(access_log, Path(build_artifact_dir, "access_log"))


if __name__ == "__main__":
    main()
