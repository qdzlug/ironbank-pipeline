import os
import re
import sys
import json
import time
import datetime
import argparse
import subprocess
from pathlib import Path
from base64 import b64decode

from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.container_tools.buildah import Buildah
from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.utils import logger

log = logger.setup("build")

# resource_type set to file by default so image is explicitly set
# resource_type is not used unless value = image, but it is set to file for clarity of purpose
# TODO: consider passing a true "type" for resource_type (i.e. resource_type = Image or resource_type = Path)
def load_resources(
    resource_dir: str, resource_type: str = "file", skopeo: Skopeo = None
):
    for resource_file in os.listdir(resource_dir):
        resource_file_obj = Path(resource_dir, resource_file)
        if resource_file_obj.isfile() and not resource_file_obj.is_symlink():
            if resource_type == "image" and skopeo:
                manifest_json = subprocess.run(
                    ["tar", "-xf", resource_file_obj.as_posix(), "-O", "manifest.json"]
                )
                image_name = manifest_json[0]["RepoTags"]
                skopeo.copy(
                    ImageFile(file_path=resource_file_obj, transport="docker-archive:"),
                    Image(url=image_name, transport="containers-storage:"),
                )
            else:
                os.rename(resource_file_obj, Path(resource_file))
        else:
            log.error("Resource type is invalid")
            sys.exit(1)


def start_squid(squid_conf: Path):
    parse_cmd = ["squid", "-k", "parse", "-f", squid_conf]
    start_cmd = ["squid", "-f", squid_conf]
    for cmd in [parse_cmd, start_cmd]:
        subprocess.run(cmd)
    # squid will not start properly without this
    time.sleep(5)

# decode technically isn't a keyword, but it is a method of str
# using PEP8 convention for avoiding builtin conflicts
def generate_auth_file(auth: str, file_path: Path | str, decode_: function = None):
    assert isinstance(file_path, Path)
    auth = decode_(auth) if decode_ else auth

    with file_path.open("a+") as f:
        f.write(auth)

def main():
    parser = argparse.ArgumentParser(
        description="Script used for building ironbank images"
    )
    parser.add_argument(
        "--imported-artifacts-path",
        "--imports-path",
        default=Path(f"{os.environ['ARTIFACT_STORAGE']}", "import-artifacts"),
        type=str,
        help="path to imported binaries and images",
    )

    args = parser.parse_args()

    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    staging_image = Image(
        registry=os.environ["REGISTRY_URL_STAGING"],
        name=os.environ["IMAGE_NAME"],
        tag=f"ibci-{os.environ['CI_PIPELINE_ID']}",
    )

    base_registry = os.environ["BASE_REGISTRY"]
    prod_auth_path = Path('/tmp/prod_auth.json')
    staging_auth_path = Path('/tmp/staging_auth.json')
    pull_creds = None
    parent_label = None
    image_dir = Path(f"{args.imports_path}/images")
    resource_dir = Path(f"{args.imports_path}/external_resources")

    os.makedirs(Path(os.environ["ARTIFACT_DIR"]))

    log.info("Determine source registry based on branch")
    if os.environ.get("STAGING_BASE_IMAGE"):
        base_registry += "-staging"
        pull_creds = os.environ["DOCKER_AUTH_CONFIG_STAGING"]
    else:
        pull_creds = os.environ["DOCKER_AUTH_CONFIG_PULL"]

    # generate read only auth file for prod registry
    generate_auth_file(auth=pull_creds, file_path=prod_auth_path, decode_=b64decode)

    # generate read write auth file for staging registry
    generate_auth_file(auth=os.environ['DOCKER_AUTH_CONFIG_STAGING'], file_path=staging_auth_path, decode_=b64decode)

    buildah = Buildah(authfile=prod_auth_path)
    skopeo = Skopeo()


    # gather files and subpaths
    log.info("Load any images used in Dockerfile build")
    load_resources(resource_dir=image_dir, resource_type="image", skopeo=skopeo)
    log.info("Load HTTP and S3 external resources")
    load_resources(resource_dir=resource_dir)

    full_build_path = Path(
        os.environ["PIPELINE_REPO_DIR"], "stages", "build"
    ).absolute()

    # add mounts to mounts.conf
    mounts = []
    mount_conf_path = Path().home().joinpath(".config", "containers", "mounts.conf")
    if os.environ.get("DISTRO_REPO_DIR"):
        mounts.append(
            full_build_path
            / f"{os.environ['DISTRO_REPO_DIR']}:{os.environ['DISTRO_REPO_MOUNT']}"
        )
    mounts.append(full_build_path / "ruby" / ".ironbank-gemrc:.ironbank-gemrc")
    mounts.append(full_build_path / "ruby" / "bundler-conf:.bundle/config")
    with mount_conf_path.open("a+") as f:
        for mount in mounts:
            f.write(f"{mount}\n")

    # sed -i '/^FROM /r'
    dockerfile_cmd_list = []
    with Path(full_build_path / "build-args.json").open("r") as f:
        build_args = json.load(f)
        dockerfile_args = "\n".join([f"ARG {k}" for k in build_args.keys()])

    with Path("Dockerfile").open("r+") as f:
        dockerfile = f.read()
        re.sub(r"(FROM.*\n)", rf"\1{dockerfile_args}", dockerfile, count=1)
        # replace all file content with updated content
        f.seek(0)
        f.truncate()
        f.write(dockerfile_cmd_list)

    if hardening_manifest.base_image_name:
        with Path(os.environ["ARTIFACT_STORAGE"], "lint", "base_image.json").open(
            "r"
        ) as f:
            base_sha = json.load(f)["BASE_SHA"]
        parent_label = f"{base_registry}/{hardening_manifest.base_image_name}:{hardening_manifest.base_image_tag}@{base_sha}"

    http_proxies = {
        "http_proxy": "http://localhost:3128",
        "HTTP_PROXY": "http://localhost:3128",
    }

    ib_labels = {
        "maintainer": "ironbank@dsop.io",
        # provide time in format YYYY-MM-DD HH:mm:SS+00:00 where +00:00 is the utc delta
        # .now() with tz passed provides an aware object whereas .utcnow() provides a naive object
        "org.opencontainers.image.created": datetime.datetime.now(datetime.timezone.utc).isoformat(sep=' ', timespec='seconds'),
        "org.opencontainers.image.source": os.environ["CI_PROJECT_URL"],
        "org.opencontainers.image.revision": os.environ["CI_COMMIT_SHA"],
    }
    if parent_label:
        ib_labels["mil.dso.ironbank.image.parent"] = parent_label

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
        format_='oci',
        log_level='warn',
        default_mounts_file=mount_conf_path,
        storage_driver='vfs',
        tag=staging_image
    )

    # Instantiate new objects from existing staging image attributes
    src = Image.from_image(staging_image, transport='container-storage:')
    dest = Image.from_image(staging_image, transport='docker://')

    skopeo.copy(src=src, dest=dest, dest_authfile=staging_auth_path)

    # TODO: decide if we need to push tags on staging_base_image or development
    if os.environ['STAGING_BASE_IMAGE'] or os.environ['CI_COMMIT_BRANCH'] == "development":
        for t in hardening_manifest.image_tags:
            dest = Image.from_image(dest, tag=t)
            skopeo.copy(src, dest, dest_authfile=staging_auth_path)

    local_image_details = json.loads(buildah.inspect(image=src, storage_driver='vfs'))

    with Path('build.env').open('a+') as f:
        f.writelines(
            [

                f"IMAGE_ID={local_image_details['FromImageID']}",
                f"IMAGE_PODMAN_SHA={}",
                f"IMAGE_FULLTAG={staging_image}",
                f"IMAGE_NAME={os.environ['IMAGE_NAME']}",
                # using utcnow because we want to use the naive format (i.e. no tz delta of +00:00)
                f"BUILD_DATE={datetime.datetime.utcnow().isoformat(sep='T', timespec='seconds')}Z"
            ]
        )
    # requires octal format of 644 to convert to decimal
    # functionally equivalent to int('644', base=8)
    Path('access.log').chmod(0o644, follow_symlinks=False)



if __name__ == "__main__":
    main()
