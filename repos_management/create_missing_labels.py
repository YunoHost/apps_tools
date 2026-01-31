#!/usr/bin/env python3

import sys
import argparse
import toml
from pathlib import Path
from github import Github

# add apps/tools to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))
from appslib import get_apps_repo as get_apps_repo

TOOLS_DIR = Path(__file__).resolve().parent.parent

# API token for yunohost-bot
token = (TOOLS_DIR / ".github_token").open("r", encoding="utf-8").read().strip()
g = Github(token, retry=None)


def create_missing_labels(args):
    apps_repo_dir = get_apps_repo.from_args(args)
    catalog = toml.load(apps_repo_dir / "apps.toml")

    o = g.get_organization("yunohost-apps")
    for repo in o.get_repos():
        if not repo.name.endswith("_ynh") or repo.name.startswith("yunohost_"):
            continue

        app = repo.name.replace("_ynh", "").lower()

        if app not in catalog:
            continue

        print(app)

        repo_labels = [label.name for label in repo.get_labels()]

        if "linter warning" not in repo_labels:
            repo.create_label("linter warning", "fbca04")

        if "linter error" not in repo_labels:
            repo.create_label("linter error", "aa0000")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true")
    get_apps_repo.add_args(parser, allow_temp=False)
    args = parser.parse_args()
    create_missing_labels(args)


if __name__ == "__main__":
    main()
