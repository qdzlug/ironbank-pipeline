import json
import os
import re
from pathlib import Path
from threading import Thread

import requests
import semver
from common.docker.v2_api import DockerV2Api

# Some spaghetti code for gathering all repos, tags (per repo), and latest tag (per repo) in the harbor ironbank project


def set_tags_in_thread(repo: str, all_tags: dict, docker_api: DockerV2Api) -> None:
    all_tags[repo] = [tag for tag in docker_api.get_tags(repo)]


repo_file_path = Path("repos.json")
tags_file_path = Path("tags.json")
latest_tags_file_path = Path("latest_tags.json")
# ten minutes
REQUEST_TIMEOUT = 600
MAX_ASYNC = 100
REPO_API_URL = "https://registry1.dso.mil/api/v2.0/projects/ironbank/repositories"
PAGE_SIZE = 100

# auth should be base64 encoded un:pw
docker_api = DockerV2Api(
    registry_url="https://registry1.dso.mil",
    basic_auth=os.environ["REGISTRY_AUTH"],
    validate=False,
)
docker_api.session.mount(
    "https://",
    requests.adapters.HTTPAdapter(pool_connections=MAX_ASYNC, pool_maxsize=MAX_ASYNC),
)

print("Gathering all repos")
if not repo_file_path.exists():
    i = 1
    response = requests.get(
        headers={"Authorization": f"Basic {os.environ['HARBOR_AUTH']}"},
        url=f"{REPO_API_URL}?page={i}&page_size={PAGE_SIZE}",
        timeout=REQUEST_TIMEOUT,
    )
    repos = [repo["name"] for repo in response.json()]
    while response.status_code == 200 and response.json():
        print(f"{REPO_API_URL}?page={i}&page_size={PAGE_SIZE}")
        i += 1
        response = requests.get(
            headers={"Authorization": f"Basic {os.environ['HARBOR_AUTH']}"},
            url=f"{REPO_API_URL}?page={i}&page_size={PAGE_SIZE}",
            timeout=REQUEST_TIMEOUT,
        )
        repos += [repo["name"] for repo in response.json()]
    repo_file_path.write_text(json.dumps(repos), encoding="utf-8")
else:
    repos = json.loads(repo_file_path.read_text(encoding="utf-8"))


all_tags: dict = {}
if not tags_file_path.exists():
    print("Gathering all tags")
    while repos:
        print(f"{len(repos)} repos left to process")
        threads = []
        for repo in repos[:MAX_ASYNC]:
            thread = Thread(
                target=set_tags_in_thread, args=(repo, all_tags, docker_api)
            )
            thread.start()
            threads.append(thread)
            print(repo)
        repos = repos[MAX_ASYNC:]
        print(len(repos))
        while threads:
            for thread in threads:
                completed = []
                if not thread.is_alive():
                    thread.join()
                    completed.append(thread)
            for thread in completed:
                threads.remove(thread)
    tags_file_path.write_text(json.dumps(all_tags), encoding="utf-8")
else:
    all_tags = json.loads(tags_file_path.read_text(encoding="utf-8"))


print("Parsing out latest tag for each repo")
latest_tags: dict = {}
for name, tags in all_tags.items():
    latest_tags[name] = None
    for tag in tags:
        if tag == "latest":
            latest_tags[name] = tag
    if not latest_tags[name]:
        # get semver or string list, sort and grab latest
        semver_tags = []
        for tag in tags:
            if not re.match(r"^([A-Za-z]+|[0-9]+(.[0-9]+){0,1})$", tag):
                try:
                    semver_tags.append(
                        semver.Version.parse(re.sub(r"^[a-zA-Z\-]+", r"", tag))
                    )
                # allow failed parsing for semver
                except ValueError as e:
                    pass
        if not semver_tags:
            # if no semver found, sort by tag strings
            for tag in tags:
                semver_tags.append(tag)
        semver_tags.sort()
        latest_tags[name] = str(semver_tags[-1])


latest_tags_file_path.write_text(json.dumps(latest_tags), encoding="utf-8")
