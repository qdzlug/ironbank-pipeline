import os
import subprocess
import sys
from typing import Any
import typing
import yaml
from pathlib import Path
from git import Repo, Remote, IndexFile
from git.exc import GitError
from git.config import GitConfigParser
from jinja2 import Environment, FileSystemLoader, Template
import shutil
import gitlab
import functools
from gitlab.v4.objects import (
    Project as GLProject,
    Group as GLGroup,
    ProjectPipeline as GLPipeline,
)
import requests
import urllib
from dataclasses import dataclass, field
from datetime import datetime, timedelta


def git_error_handler(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except GitError as e:
            print(
                "\x1b[38;5;226mNote: Removing the clone_dir directory may resolve git-related errors. If you're unsure which directory this is, check the clone_dir value in the config.yaml"
            )
            raise e from None

    return wrapper


@dataclass
class Project:
    """
    Manages all configuration and artifacts associated with project
    Attributes:
    - src_path: path in src repository, (e.g. for repo1.dso.mil/dsop/redhat/ubi/ubi8 this value should be redhat/ubi/ubi8) and config.group should be `dsop`
    - dest_project_name: project name to use for dest, does not support nested paths (i.e. test/test1 is not supported)
    - branch: project branch that will be used for running pipelines (default is master)
    - base_image: set to True if using a base image project, sets LABEL_ALLOWLIST_REGEX after creating project

    - repo: Local repo associated with project
    - remote: Remote destination repo
    - gl_project: Destination gitlab project
    - pipeline: Pipeline created for project in destination
    - changes_pushed: set to True if new changes were pushed to destination, prevents automated pipeline creation since one will be created with the pushed changes
    """

    # from config
    src_path: str
    dest_project_name: str | Any = None
    # TODO: make appropriate typing fixes to set these as Optional
    branch: str | Any = "master"
    base_image: bool = False

    # generated during script run
    repo: Repo | Any = None
    remote: Remote | Any = None
    gl_project: GLProject | Any = None
    pipeline: GLPipeline | Any = None
    changes_pushed: bool = False

    def __post_init__(self) -> None:
        self.dest_project_name = (
            self.dest_project_name or self.src_path.rsplit("/", maxsplit=1)[-1]
        )
        assert "/" not in self.dest_project_name


@dataclass
class Config:
    """
    Represents deserialized config.yaml+secrets.yaml
    Manages Project objects used in this script

    Any edits to config.yaml or secrets.yaml affect the instantiation of this class
    Any changes to this class should be reflected in config.yaml or secrets.yaml where appropriate

    Attributes:

    config.yaml
    - tester: name of the tester using this script, used to create a group in destination
    - pipeline_branch: pipeline branch to test against
    - src_gitlab_url: source url to retrieve repos from (examples: https://repo1.dso.mil or repo1.dso.mil -- both should work)
    - dest_gitlab_url: dest url to use for running test pipelines (examples: https://code-ib-zelda.staging.dso.mil or code-ib-zelda.staging.dso.mil -- both should work)
    - group: top level group to gather projects from and push to, should be "dsop" in most cases, but could be changed to something like ironbank-tools if testing automation against those projects
    - template: template directory used for jinja templating the .gitlab-ci.yml file
    - default_project_branch: default branch to use for each project if no branch is specified
    - projects: list of projects to use for testing

    - proxies: not currently set in the config since this script will pretty much always require a proxy, can be added to the config if needed

    secrets.yaml -- can use secrets.yaml.example for the template
    - src_un: source repo username
    - src_pw: source repo access token
    - dest_un: dest repo username
    - dest_pw: dest repo access token
    """

    tester: str
    pipeline_branch: str
    src_gitlab_url: str
    dest_gitlab_url: str
    group: str
    clone_dir: Path
    ci_file: str
    templates: str | Path
    default_project_branch: str
    # TODO: update where necessary to set this as list[Project] | list[dict[str, str]]
    projects: list[Project] | Any
    proxies: dict[str, str] = field(
        default_factory=lambda: {
            "https": "socks5h://127.0.0.1:12345",
            "http": "socks5h://127.0.0.1:12345",
        }
    )
    src_un: str = field(default_factory=lambda: os.environ.get("SRC_UN", ""))
    src_pw: str = field(default_factory=lambda: os.environ.get("SRC_PW", ""))
    dest_un: str = field(default_factory=lambda: os.environ.get("DEST_UN", ""))
    dest_pw: str = field(default_factory=lambda: os.environ.get("DEST_PW", ""))

    # TODO: remove this decorator when typing is resolved for self.projects
    @typing.no_type_check
    def __post_init__(self) -> None:
        # convert project dictionaries to project objects
        self.projects = [
            Project(
                **{
                    **project,
                    "branch": project.get("branch") or self.default_project_branch,
                }
            )
            for project in self.projects
        ]
        self.clone_dir = Path(self.clone_dir)
        self.templates = Path(self.templates)
        # remove https or http prefix since they'll be added again for each url
        self.src_gitlab_url = self.src_gitlab_url.replace("https://", "").replace(
            "http://", ""
        )
        self.dest_gitlab_url = self.dest_gitlab_url.replace("https://", "").replace(
            "http://", ""
        )
        self.src_auth_exists = bool(self.src_un and self.src_pw)
        self.dest_auth_exists = bool(self.dest_un and self.dest_pw)
        self.src_url_prefix = (
            f"https://{self.src_un}:{urllib.parse.quote(self.src_pw, safe='')}@"
            if self.src_auth_exists
            else "https://"
        )
        self.dest_url_prefix = (
            f"https://{self.dest_un}:{urllib.parse.quote(self.dest_pw, safe='')}@"
            if self.dest_auth_exists
            else "https://"
        )
        # configure auth for git pulls from src and pushes to dest
        self.src_git_url: str = f"{self.src_url_prefix}{self.src_gitlab_url}"
        self.dest_git_url: str = f"{self.dest_url_prefix}{self.dest_gitlab_url}"
        self.src_gitlab_url = f"https://{self.src_gitlab_url}"
        self.dest_gitlab_url = f"https://{self.dest_gitlab_url}"

        if not self.dest_auth_exists:
            print(
                "WARNING: Destination authentication not provided. Keychain auth will be used for git if configured"
            )
        if not self.src_auth_exists:
            print(
                "WARNING: Source authentication not provided. Keychain auth will be used for git if configured"
            )

        # validate values aren't misconfigured
        for url in [self.dest_gitlab_url, self.dest_git_url, self.dest]:
            assert "repo1" not in url
        assert self.tester

    @property
    def src(self) -> str:
        """
        Alias to src_gitlab_url
        """
        return self.src_gitlab_url

    @property
    def dest(self) -> str:
        """
        Alias to dest_gitlab_url
        """
        return self.dest_gitlab_url


@git_error_handler
def clone_from_src(config: Config) -> Config:
    """
    Clone all src repos to a local directory defined in config
    Instatiates each project's repo object
    """
    config.clone_dir.mkdir(parents=True, exist_ok=True)

    for project in config.projects:
        clone_url: str = f"{config.src_git_url}/{config.group}/{project.src_path}"
        dest_dir: Path = Path(f"{config.clone_dir}/{project.dest_project_name}")
        print(clone_url)
        if not dest_dir.exists():
            repo: Repo = Repo.clone_from(clone_url, dest_dir)
            assert repo
            project.repo = repo
        else:
            repo = Repo(dest_dir)
            assert repo
            project.repo = Repo(dest_dir)
    return config


def template_ci_file(config: Config) -> Path:
    """
    Template .gitlab-ci.yml with expected pipeline branch
    """
    environment: Environment = Environment(loader=FileSystemLoader(config.templates))

    template: Template = environment.get_template(f"{config.ci_file}.j2")
    ci_file_content: str = template.render(branch=config.pipeline_branch)
    template_ci_file_path: Path = Path(config.templates, config.ci_file)

    with template_ci_file_path.open("w", encoding="utf-8") as f:
        f.write(ci_file_content)
    return template_ci_file_path


def create_tester_group_in_dest(gl: gitlab.Gitlab, config: Config) -> GLGroup:
    """
    For tester (i.e. `tester` field in config.yaml)
    - Check for existing group in destination gl instance
    - If group does not exist, create it
    """
    assert "repo1" not in gl.api_url
    try:
        group: GLGroup = gl.groups.get(f"{config.group}/{config.tester}")
        print(f"{config.group}/{config.tester}")
        group.visibility = "public"
        group.save()
    except gitlab.GitlabGetError:
        print("Could not retrieve group. Attempting to create...")
        gl.groups.create(
            {
                "name": config.tester,
                "path": config.tester,
                "parent_id": gl.groups.get(config.group).id,
            }
        )
        group = gl.groups.get(f"{config.group}/{config.tester}")
        group.visibility = "public"
        group.save()
    except gitlab.GitlabAuthenticationError:
        print(
            "Authentication error. Please update your dest auth in secrets.yaml or run `export DEST_UN=<username>` and `export DEST_PW=<rw_access_token>` before rerunning"
        )
        sys.exit(1)
    assert group
    return group


def update_force_push_rules(project: GLProject, branch: str) -> None:
    """
    Update project branch to allow force push
    """
    project.protectedbranches.delete(branch)
    maintainer = gitlab.const.MAINTAINER_ACCESS
    project.protectedbranches.create(
        {
            "name": "master",
            "merge_access_level": maintainer,
            "push_access_level": maintainer,
            "allow_force_push": True,
        }
    )


def generate_remote(project: Project, repo: Repo, config: Config) -> Remote:
    """
    Create remote from repo if not exists, else return existing remote
    """
    return (
        repo.create_remote(
            "staging",
            f"{config.dest_git_url}/{config.group}/{config.tester}/{project.dest_project_name}",
        )
        if "staging" not in [remote.name for remote in repo.remotes]
        else repo.remotes.staging
    )


def push_branches(project: Project, repo: Repo, remote: Remote) -> None:
    """
    Push project branch to destination, and development if not exists
    Development must be pushed for trufflehog to function correctly
    """
    branches = [project.branch]
    branches += (
        ["development"]
        if "development" not in [ref.name.split("staging/") for ref in remote.refs]
        else []
    )
    for branch in branches:
        print(branch)
        repo.git.checkout(branch)
        remote.push(force=True).raise_if_error()


@git_error_handler
def push_repos_to_dest(config: Config) -> Config:
    """
    Configures projects for destination and pushes them to destination
    Instatiates each project's remote object
    - Template ci file
    - Pull changes from source
    - Delete/Recreate updated ci file for each project
    - If diff in ci file or ci file created for the first time
        - Add ci file
        - Commit changes
        - Push to destination
        - Set changes_pushed for project to True
    """
    template_ci_file_path = template_ci_file(config)
    for project in config.projects:
        repo: Repo = project.repo
        assert repo.working_dir
        # check out test branch before proceeding (prevent making changes to last branch used)
        repo.git.checkout(project.branch)
        repo_path: Path = Path(repo.working_dir)
        repo_ci_file: Path = Path(repo_path, config.ci_file)
        # pull any changes from origin
        repo.remotes.origin.pull()
        # delete existing file and copy again
        # creates no diff if no changes exist
        repo_ci_file.unlink(missing_ok=True)
        shutil.copy2(template_ci_file_path, repo_ci_file)
        # add change to ci file and commit
        index: IndexFile = repo.index
        # if unstaged changes or untracked files
        if index.diff(None) or repo.untracked_files:
            # only add ci file, prevent adding unexpected files
            index.add([config.ci_file])
            index.commit("updating .gitlab-ci.yml")
            remote = generate_remote(project, repo, config)
            project.remote = remote
            remote_urls = [url for url in remote.urls]
            # double check repo1 not in dest before push
            print(remote_urls[0].split("@")[-1])
            assert len(remote_urls) == 1 and "repo1" not in remote_urls[0]
            push_branches(project, repo, remote)
            project.changes_pushed = True
        else:
            print(
                f"Nothing to push to staging for {project.dest_project_name}. Skipping"
            )
    return config


def update_dest_project_permissions(gl: gitlab.Gitlab, config: Config) -> Config:
    """
    Updates destination project permissions as necessary for pipeline to function
    Instatiates each project's gl_project object
    - Make project public
    - Allow force push for branch
    - Add LABEL_ALLOWLIST_REGEX for base images
    """
    assert "repo1" not in gl.api_url
    for project in config.projects:
        gl_project: GLProject = gl.projects.get(
            f"{config.group}/{config.tester}/{project.dest_project_name}"
        )
        assert gl_project
        # TODO: add caching to skip these steps
        print(f"Updating permissions for {project.dest_project_name}")
        gl_project.visibility = "public"
        gl_project.save()
        update_force_push_rules(gl_project, project.branch)
        if project.base_image:
            variable_exists = "LABEL_ALLOWLIST_REGEX" in [
                var.key for var in gl_project.variables.list()
            ]
            if not variable_exists:
                gl_project.variables.create(
                    {
                        "key": "LABEL_ALLOWLIST_REGEX",
                        "value": r"^mil\.dso\.ironbank\.os-type$",
                    }
                )
        project.gl_project = gl_project
    return config


def kickoff_pipelines(config: Config) -> Config:
    """
    Kick's off pipelines for any projects that haven't pushed changes
    Instatiates each project's pipeline object
    """
    for project in config.projects:
        # prevent kicking off second pipeline if ci changes were pushed to remote
        if not project.changes_pushed:
            print(f"Kicking off pipeline for {project.dest_project_name}")
            project.pipeline = project.gl_project.pipelines.create(
                {"ref": project.branch}
            )
        else:
            # pipeline should've been created when changes were pushed
            print(
                f"Skipping pipeline creation for {project.dest_project_name}. Pipeline already created."  # noqa E501
            )
    return config


def open_urls(config: Config) -> None:
    # need to do imports here to avoid breaking this for people who don't have selenium/geckodriver installed
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.common.proxy import Proxy

    options = Options()
    # options.headless = True
    # uncomment for local testing
    options.proxy = Proxy(
        {
            "socksProxy": f"{os.environ.get('SOCKS_HOST', 'localhost')}:12345",
            "socksVersion": 5,
        }
    )
    options.set_preference("network.proxy.socks_remote_dns", True)
    driver = webdriver.Firefox(options=options)
    for project in config.projects:
        driver.get(project.pipeline.web_url)
        if project != config.projects[-1]:
            driver.switch_to.new_window()


def main() -> None:
    """
    Main function
    - Generate config
    - Create gl object
    - Clone repos from source
    - Create tester group
    - Push repos to destination
    - Update destination repo permissions
    - Kickoff pipelines for anything that didn't push changes
    """
    config_files = ["config.yaml", "secrets.yaml"]
    config_args = []
    for conf in config_files:
        with Path(conf).open("r", encoding="utf-8") as f:
            config_args += [yaml.safe_load(f)]

    config = Config(**{k: v for sub_dict in config_args for k, v in sub_dict.items()})

    session = requests.session()
    if config.proxies:
        session.proxies.update(config.proxies)

    if not config.dest_pw:
        print(
            "WARNING: gitlab object configured without access token. Some functionality in this script may not work"
        )

    dest_gl = gitlab.Gitlab(
        url=config.dest, private_token=config.dest_pw, session=session
    )

    assert isinstance(config.clone_dir, Path)

    print("\nCloning repos...")
    config = clone_from_src(config)

    print("\nCreating group...")
    create_tester_group_in_dest(dest_gl, config)

    # TODO: check git config before updating it

    conf_parser = GitConfigParser(config_level="global")
    proxy_val = conf_parser.get_value(section="http", option="proxy", default="")

    if not proxy_val and config.proxies:
        subprocess.run(
            ["git", "config", "--global", "http.proxy", "socks5h://localhost:12345"],
            check=True,
        )

    print(f"\nPushing repos to {config.dest}...")
    config = push_repos_to_dest(config)

    print("\nUpdating destination project permissions")
    config = update_dest_project_permissions(dest_gl, config)

    # TODO: check git config before updating it
    if not proxy_val and config.proxies:
        subprocess.run(
            ["git", "config", "--global", "--unset", "http.proxy"], check=True
        )

    print("\nKicking off Pipelines...")
    config = kickoff_pipelines(config)

    print("\nPipeline links:")
    for project in config.projects:
        if project.changes_pushed:
            pipelines = project.gl_project.pipelines.list(
                updated_after=str(datetime.now() - timedelta(minutes=2))
            )
            assert isinstance(pipelines, list)
            project.pipeline = pipelines[0]
        print(project.pipeline.web_url)

    open_urls_in_firefox = input(
        "\nDo you want to open these urls in firefox and do you have the required gecko driver installed?\n"
    )

    if open_urls_in_firefox.lower() in ["y", "yes"]:
        open_urls(config)


if __name__ == "__main__":
    main()
