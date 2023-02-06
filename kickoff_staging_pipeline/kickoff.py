import os
import subprocess
import sys
import yaml
from pathlib import Path
from git import Repo
from jinja2 import Environment, FileSystemLoader, Template
import shutil
import gitlab
import requests
import urllib
from dataclasses import dataclass, field


@dataclass
class Config:
    tester: str
    branch: str
    src_gitlab_url: str
    dest_gitlab_url: str
    group: str
    clone_dir: str | Path
    ci_file: str
    templates: str | Path
    default_project_branch: str
    projects: list[str]
    proxies: dict[str] = field(
        default_factory=lambda: {
            "https": "socks5h://127.0.0.1:12345",
            "http": "socks5h://127.0.0.1:12345",
        }
    )
    src_un: str = field(default_factory=lambda: os.environ["SRC_UN"])
    src_pw: str = field(default_factory=lambda: os.environ["SRC_PW"])
    dest_un: str = field(default_factory=lambda: os.environ["DEST_UN"])
    dest_pw: str = field(default_factory=lambda: os.environ["DEST_PW"])

    def __post_init__(self) -> None:
        assert "repo1" not in self.dest_gitlab_url
        assert self.tester
        self.clone_dir = Path(self.clone_dir)
        self.templates = Path(self.templates)
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
        self.src_git_url = f"{self.src_url_prefix}{self.src_gitlab_url}"
        self.dest_git_url = f"{self.dest_url_prefix}{self.dest_gitlab_url}"
        self.src_gitlab_url = f"https://{self.src_gitlab_url}"
        self.dest_gitlab_url = f"https://{self.dest_gitlab_url}"

    @property
    def src(self) -> str:
        return self.src_gitlab_url

    @property
    def dest(self) -> str:
        return self.dest_gitlab_url


def clone_from_src(config: Config) -> list[Repo]:
    config.clone_dir.mkdir(parents=True, exist_ok=True)

    for project, i in zip(config.projects, range(len(config.projects))):
        clone_url: str = f"{config.src_git_url}/{config.group}/{project}"
        dest_dir: Path = Path(f"{config.clone_dir}/{project.split('/')[-1]}")
        print(clone_url)
        if not dest_dir.exists():
            repo: Repo = Repo.clone_from(clone_url, dest_dir)
            assert repo
            config.projects[i]["repo"] = repo
        else:
            repo = Repo(dest_dir)
            assert repo
            config.projects[i]["repo"] = Repo(dest_dir)
    return config


def template_ci_file(config: Config):
    environment: Environment = Environment(loader=FileSystemLoader(config.templates))

    template: Template = environment.get_template(f"{config.ci_file}.j2")
    ci_file_content: str = template.render(branch=config.branch)
    template_ci_file: Path = Path(config.templates, config.ci_file)

    with template_ci_file.open("w") as f:
        f.write(ci_file_content)
    return ci_file_content


def create_tester_group_in_dest(gl: gitlab.Gitlab, config: Config):
    """
    For tester (i.e. `tester` field in config.yaml)
    - Check for existing group in destination gl instance
    - If group does not exist, create it
    """

    try:
        group = gl.groups.get(f"{config.group}/{config.tester}")
    except gitlab.GitlabGetError:
        print("Could not retrieve group. Attempting to create...")
        group = gl.groups.create({"name": config.tester, "path": config.group})
    except gitlab.GitlabAuthenticationError:
        print(
            "Authentication error. Please run `export STAGING_GL_TOKEN=<your_rw_access_token>` before rerunning"
        )
        sys.exit(1)
    assert group
    return group


def push_repos_to_dest(config: Config):
    for project, i in zip(config.projects, range(len(config.projects))):
        repo = project["repo"]
        assert repo.working_dir
        repo.git.checkout(project.get("branch") or config.default_project_branch)
        repo_path: Path = Path(repo.working_dir)
        repo_ci_file: Path = Path(repo_path, config.ci_file)
        repo_ci_file.unlink(missing_ok=True)
        shutil.copy2(repo_ci_file, template_ci_file)
        index = repo.index
        index.add(config.ci_file)
        index.commit("updating .gitlab-ci.yml")
        remote = (
            repo.create_remote(
                "staging",
                f"{config.dest_git_url}/{config.group}/{config.tester}/{project['dest_project_name']}",
            )
            if "staging" not in [remote.name for remote in repo.remotes]
            else repo.remotes.staging
        )
        config.projects[i]["remote"] = remote
        # remote.push()
    return config


def get_projects_from_dest(gl: gitlab.Gitlab, config: Config):
    for project, i in zip(config.projects, range(len(config.projects))):
        config.projects[i]["gl_project"] = gl.projects.get(
            f"{config.group}/{config.tester}/{config.dest_project_name}"
        )
    return config


def kickoff_pipelines(config: Config):
    for project, i in zip(config.projects, range(len(config.projects))):
        config.projects[i]["pipeline"] = project["gl_project"].pipelines.create(
            {"ref": project.get("branch") or config.default_project_branch}
        )
    return config


def main():

    config_files = ["config.yaml", "secrets.yaml"]
    config_args = []
    for cf in config_files:
        with Path(cf).open("r", encoding="utf-8") as f:
            config_args += [yaml.safe_load(f)]

    config = Config(**{k: v for sub_dict in config_args for k, v in sub_dict.items()})

    session = requests.session()
    if config.proxies:
        session.proxies.update(config.proxies)

    dest_gl = gitlab.Gitlab(
        url=config.dest, private_token=config.dest_pw, session=session
    )

    assert isinstance(config.clone_dir, Path)

    config = clone_from_src(config)

    create_tester_group_in_dest(dest_gl, config)

    # TODO: check git config before updating it
    if config.proxies:
        subprocess.run(
            ["git", "config", "--global", "http.proxy", "socks5h://localhost:12345"]
        )

    config = push_repos_to_dest(config)

    # TODO: check git config before updating it
    if config.proxies:
        subprocess.run(["git", "config", "--global", "--unset", "http.proxy"])

    config = get_projects_from_dest(dest_gl, config)

    config = kickoff_pipelines(config)


if __name__ == "__main__":
    main()
