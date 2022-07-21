from base64 import b64decode
import os
import json
import pathlib
import subprocess

from ironbank.pipeline.utils import logger

log = logger.setup(name="skopeo")


class Skopeo:
    def pull_auth(self) -> str:
        if os.environ.get("STAGING_BASE_IMAGE"):
            auth_file = "staging_pull_auth.json"
            # Grab prod pull docker auth
            pull_auth = b64decode(os.environ["DOCKER_AUTH_CONFIG_STAGING"]).decode(
                "UTF-8"
            )
            pathlib.Path(auth_file).write_text(pull_auth)
        else:
            auth_file = "prod_pull_auth.json"
            # Grab staging docker auth
            pull_auth = b64decode(os.environ["DOCKER_AUTH_CONFIG_PULL"]).decode("UTF-8")
            pathlib.Path(auth_file).write_text(pull_auth)
        return auth_file

    def inspect(self, image, tag) -> dict:

        auth_file = self.pull_auth()
        registry = "ironbank-staging" if ("staging" in auth_file) else "ironbank"

        cmd = [
            "skopeo",
            "inspect",
            "--authfile",
            auth_file,
            f"docker://registry1.dso.mil/{registry}/{image}:{tag}",
        ]
        log.info(f"Run inspect cmd: {cmd}")
        # if skopeo inspect fails, because IMAGE value doesn't match a registry1 container name
        #   fail back to using existing functionality

        sha_value = subprocess.run(
            args=cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            encoding="utf-8",
        )
        return json.loads(sha_value.stdout)
