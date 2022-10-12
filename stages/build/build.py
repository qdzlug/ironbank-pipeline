import os
import re
import sys
import json
import time
import shutil
import datetime
import subprocess
from pathlib import Path
from base64 import b64decode
from typing import Callable

from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.container_tools.buildah import Buildah
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.decorators import subprocess_error_handler

log = logger.setup("build")


def write_dockerfile_args(dockerfile_args: list["str"]):
    with Path("Dockerfile").open("r+") as f:
        dockerfile_content = []
        from_found = False
        for line in f.readlines():
            dockerfile_content.append(line)
            if re.match(r"^FROM", line) and not from_found:
                from_found = True
                dockerfile_content += dockerfile_args
        # replace all file content with updated content
        f.seek(0)
        f.truncate()
        f.writelines(dockerfile_content)


def create_mounts(mount_conf_path: Path, pipeline_build_dir: Path):
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
def load_resources(
    resource_dir: str, resource_type: str = "file", skopeo: Skopeo = None
):
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
                log.info(f"loading image {resource_file_obj}")
                skopeo.copy(
                    ImageFile(file_path=resource_file_obj, transport="docker-archive:"),
                    Image(url=image_url, transport="containers-storage:"),
                )
            else:
                os.rename(resource_file_obj, Path(resource_file))
        else:
            log.error("Resource type is invalid")
            sys.exit(1)


def get_parent_label(
    artifact_storage_dir: Path,
    hardening_manifest: HardeningManifest,
    base_registry: str,
):
    if hardening_manifest.base_image_name:
        with Path(artifact_storage_dir, "lint", "base_image.json").open("r") as f:
            base_sha = json.load(f)["BASE_SHA"]
        return f"{base_registry}/{hardening_manifest.base_image_name}:{hardening_manifest.base_image_tag}@{base_sha}"


def start_squid(squid_conf: Path):
    parse_cmd = ["squid", "-k", "parse", "-f", squid_conf]
    start_cmd = ["squid", "-f", squid_conf]
    for cmd in [parse_cmd, start_cmd]:
        subprocess.run(cmd)
    # squid will not start properly without this
    time.sleep(5)


# decode technically isn't a keyword, but it is a method of str
# using PEP8 convention for avoiding builtin conflicts
def generate_auth_file(auth: str, file_path: Path | str, decode_: Callable = None):
    assert isinstance(file_path, Path)
    auth = decode_(auth) if decode_ else auth
    auth = auth.decode() if type(auth) == bytes else auth
    with file_path.open("a+") as f:
        f.write(auth)


def generate_build_env(
    image_details: dict, image_name: str, image: Image, skopeo: Skopeo
):
    with Path("build.env").open("a+") as f:
        f.writelines(
            [
                f"IMAGE_ID={image_details['FromImageID']}",
                f"IMAGE_PODMAN_SHA={skopeo.inspect(image)['Digest']}",
                f"IMAGE_FULLTAG={image}",
                f"IMAGE_NAME={image_name}",
                # using utcnow because we want to use the naive format (i.e. no tz delta of +00:00)
                f"BUILD_DATE={datetime.datetime.utcnow().isoformat(sep='T', timespec='seconds')}Z",
            ]
        )


# decorate main to capture all subprocess errors
@subprocess_error_handler(logging_message="Unexpected subprocess error caught")
def main():

    # define vars
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    staging_image = Image(
        registry=os.environ["REGISTRY_URL_STAGING"],
        name=hardening_manifest.image_name,
        tag=f"ibci-{os.environ['CI_PIPELINE_ID']}",
    )
    base_registry = os.environ["BASE_REGISTRY"]
    prod_auth_path = Path("/tmp/prod_auth.json")
    staging_auth_path = Path("/tmp/staging_auth.json")
    pull_creds = None
    parent_label = None
    artifact_storage_dir = Path(os.environ["ARTIFACT_STORAGE"])
    build_artifact_dir = Path(os.environ["ARTIFACT_DIR"])
    imports_dir = artifact_storage_dir / "import-artifacts"
    image_dir = imports_dir / "images"
    resource_dir = imports_dir / "external-resources"
    pipeline_build_dir = Path(
        os.environ["PIPELINE_REPO_DIR"], "stages", "build"
    ).absolute()
    mount_conf_path = Path().home().joinpath(".config", "containers", "mounts.conf")

    os.makedirs(build_artifact_dir)

    log.info("Determine source registry based on branch")
    if os.environ.get("STAGING_BASE_IMAGE"):
        base_registry += "-staging"
        pull_creds = os.environ["DOCKER_AUTH_CONFIG_STAGING"]
    else:
        pull_creds = os.environ["DOCKER_AUTH_CONFIG_PULL"]

    # get read only auth files
    # generate read only auth file for prod registry
    log.debug("Generating pull auth file")
    generate_auth_file(auth=pull_creds, file_path=prod_auth_path, decode_=b64decode)

    # generate read write auth file for staging registry
    log.debug("Generating staging read/write auth file")
    generate_auth_file(
        auth=os.environ["DOCKER_AUTH_CONFIG_STAGING"],
        file_path=staging_auth_path,
        decode_=b64decode,
    )

    buildah = Buildah(authfile=prod_auth_path)
    skopeo = Skopeo()

    # gather files and subpaths
    log.info("Load any images used in Dockerfile build")
    load_resources(resource_dir=image_dir, resource_type="image", skopeo=skopeo)
    log.info("Load HTTP and S3 external resources")
    load_resources(resource_dir=resource_dir)

    log.info("Converting labels from hardening manifest into command line args")

    parent_label = get_parent_label(
        artifact_storage_dir=artifact_storage_dir,
        hardening_manifest=hardening_manifest,
        base_registry=base_registry,
    )

    ib_labels = {
        "maintainer": "ironbank@dsop.io",
        # provide time in format YYYY-MM-DD HH:mm:SS+00:00 where +00:00 is the utc delta
        # .now() with tz passed provides an aware object whereas .utcnow() provides a naive object
        "org.opencontainers.image.created": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(sep=" ", timespec="seconds"),
        "org.opencontainers.image.source": os.environ["CI_PROJECT_URL"],
        "org.opencontainers.image.revision": os.environ["CI_COMMIT_SHA"],
    }
    if parent_label:
        ib_labels["mil.dso.ironbank.image.parent"] = parent_label

    log.info("Converting build args from hardening manifest into command line args")
    http_proxies = {
        "http_proxy": "http://localhost:3128",
        "HTTP_PROXY": "http://localhost:3128",
    }

    start_squid(squid_conf=Path(pipeline_build_dir, "squid.conf"))

    log.info("Adding the ironbank.repo to the container via mount.conf")
    # add mounts to mounts.conf
    create_mounts(
        mount_conf_path=mount_conf_path, pipeline_build_dir=pipeline_build_dir
    )

    # sed -i '/^FROM /r'
    with Path(pipeline_build_dir / "build-args.json").open("r") as f:
        build_args = json.load(f)
        # create list of lists, with each sublist containing an arg
        # sublist needed for f.writelines() on arg substitution in Dockerfile
        dockerfile_args = [f"ARG {k}\n" for k in build_args.keys()]

    write_dockerfile_args(dockerfile_args=dockerfile_args)

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
        tag=staging_image,
    )

    # Instantiate new objects from existing staging image attributes
    src = Image.from_image(staging_image, transport="containers-storage:")
    dest = Image.from_image(staging_image, transport="docker://")

    # TODO: skip the following skopeo copies on local build, maybe change the copy to local dir?
    skopeo.copy(
        src=src,
        dest=dest,
        digestfile=Path(build_artifact_dir / "digest"),
        dest_authfile=staging_auth_path,
    )

    # TODO: decide if we need to push tags on staging_base_image or development
    if (
        os.environ["STAGING_BASE_IMAGE"]
        or os.environ["CI_COMMIT_BRANCH"] == "development"
    ):
        for t in hardening_manifest.image_tags:
            dest = Image.from_image(dest, tag=t)
            skopeo.copy(src, dest, dest_authfile=staging_auth_path)

    local_image_details = buildah.inspect(image=src, storage_driver="vfs")

    generate_build_env(
        image_details=local_image_details,
        image_name=hardening_manifest.image_name,
        image=dest,
        skopeo=skopeo,
    )

    # requires octal format of 644 to convert to decimal
    # functionally equivalent to int('644', base=8)
    access_log = Path("access.log")
    access_log.chmod(0o644, follow_symlinks=False)
    shutil.copy(access_log, Path(build_artifact_dir, access_log))


if __name__ == "__main__":
    main()
