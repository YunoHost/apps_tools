#!/usr/bin/env python3

import sys
import argparse
import toml
from pathlib import Path
from github import Github
from datetime import datetime, timezone

# add apps/tools to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))
from appslib import get_apps_repo as get_apps_repo

TOOLS_DIR = Path(__file__).resolve().parent.parent

# API token for yunohost-bot
token = (TOOLS_DIR / ".github_token").open("r", encoding="utf-8").read().strip()
g = Github(token)


def analyze_repos(args):
    apps_repo_dir = get_apps_repo.from_args(args)
    catalog = toml.load(apps_repo_dir / "apps.toml")
    wishlist = toml.load(apps_repo_dir / "wishlist.toml")
    graveyard = toml.load(apps_repo_dir / "graveyard.toml")

    not_referenced = set()
    graveyard_should_be_archived = set()
    deprecated_and_should_be_archived = set()
    archived_but_not_deprecated_nor_in_graveyard = set()

    o = g.get_organization("yunohost-apps")
    for repo in o.get_repos():
        if not repo.name.endswith("_ynh") or repo.name.startswith("yunohost_"):
            continue

        app = repo.name.replace("_ynh", "").lower()

        if app in catalog or app in wishlist:
            infos_in_catalog = catalog.get(app, {})
            deprecated = (
                "antifeatures" in infos_in_catalog
                and "deprecated-software" in infos_in_catalog["antifeatures"]
            )
            if deprecated and not repo.archived:
                deprecated_and_should_be_archived.add((app, repo.html_url, repo))
            elif repo.archived and app in catalog and not deprecated:
                archived_but_not_deprecated_nor_in_graveyard.add(
                    (app, repo.html_url, repo)
                )

        elif app in graveyard:
            if not repo.archived:
                graveyard_should_be_archived.add((app, repo.html_url, repo))

        elif not repo.archived:
            not_referenced.add((app, repo.html_url, repo))

    print("\n\n\n")
    print(
        f"{len(graveyard_should_be_archived)} apps in the graveyard but their repo are not archived"
    )
    print("-" * 80)
    for app, url, _ in sorted(graveyard_should_be_archived):
        print(f"{app:<22} : {url}")

    print("\n\n\n")
    print(
        f"{len(deprecated_and_should_be_archived)} apps that are marked as deprecated-software in apps.toml, and their repo should be archived ?"
    )
    print("-" * 80)
    for app, url, _ in sorted(deprecated_and_should_be_archived):
        print(f"{app:<22} : {url}")

    print("\n\n\n")
    print(
        f"{len(archived_but_not_deprecated_nor_in_graveyard)} apps have their repo archived, but are not flagged as depreacted in apps.toml ?"
    )
    print("-" * 80)
    for app, url, _ in sorted(archived_but_not_deprecated_nor_in_graveyard):
        print(f"{app:<22} : {url}")

    print("\n\n\n")
    print(
        f"{len(not_referenced)} repos are neither referenced in apps.toml, wishlist.toml, graveyard.toml, and are not archived either ?"
    )
    print("-" * 80)
    for app, url, repo in sorted(not_referenced, key=lambda repo: repo[2].pushed_at):
        last_push_days_ago = (datetime.now(timezone.utc) - repo.pushed_at).days
        print(f"{app:<22} : {url}, last push {last_push_days_ago} days ago")

    if args.fix_graveyard_should_be_archived:
        for _, url, repo in sorted(graveyard_should_be_archived):
            print(f"Archiving {url} ...")
            repo.edit(archived=True)

    if (
        args.fix_archived_but_not_deprecated
        and archived_but_not_deprecated_nor_in_graveyard
    ):
        print(f"Patching {apps_repo_dir / 'apps.toml'} ...")
        for app, _, _ in sorted(archived_but_not_deprecated_nor_in_graveyard):
            if app not in catalog:
                print(f"Skipping {app}, not in catalog?")
                continue
            catalog_infos = catalog[app]
            if "antifeatures" not in catalog_infos:
                catalog_infos["antifeatures"] = []
            catalog_infos["antifeatures"].append("deprecated-software")
        toml.dump(catalog, (apps_repo_dir / "wishlist.toml").open("w"))

    if args.fix_unreferenced_should_be_archived:
        for _, url, repo in sorted(not_referenced, key=lambda repo: repo[2].pushed_at):
            last_push_days_ago = (datetime.now(timezone.utc) - repo.pushed_at).days
            if last_push_days_ago > 500:
                print(f"Archiving {url} ...")
                repo.edit(archived=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("--fix-graveyard-should-be-archived", action="store_true")
    parser.add_argument("--fix-archived-but-not-deprecated", action="store_true")
    parser.add_argument("--fix-unreferenced-should-be-archived", action="store_true")
    get_apps_repo.add_args(parser, allow_temp=False)
    args = parser.parse_args()
    analyze_repos(args)


if __name__ == "__main__":
    main()
