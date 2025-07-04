#!/usr/bin/env python3

import argparse
import copy
import json
import logging
import multiprocessing
import requests
import shutil
import subprocess
import time
from collections import OrderedDict
from functools import cache
from itertools import repeat
from pathlib import Path
from typing import Any, Optional

import toml
import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm
from git import Repo

import appslib.logging_sender  # pylint: disable=import-error
from appslib.utils import (
    get_antifeatures,  # pylint: disable=import-error
    get_catalog,
    get_categories,
)
import appslib.get_apps_repo as get_apps_repo

now = time.time()


@cache
def categories_list():
    # Load categories and reformat the structure to have a list with an "id" key
    new_categories = get_categories()
    for category_id, infos in new_categories.items():
        infos["id"] = category_id
        for subtag_id, subtag_infos in infos.get("subtags", {}).items():
            subtag_infos["id"] = subtag_id
        infos["subtags"] = list(infos.get("subtags", {}).values())
    return list(new_categories.values())


@cache
def antifeatures_list():
    # (Same for antifeatures)
    new_antifeatures = get_antifeatures()
    for antifeature_id, infos in new_antifeatures.items():
        infos["id"] = antifeature_id
    return list(new_antifeatures.values())


@cache
def dev_ci_result_per_branch():
    url = "https://ci-apps-dev.yunohost.org/ci/api/results-dev"
    try:
        return requests.get(url).json()
    except Exception as e:
        logging.error(f"[List builder] Failed to fetch the CI apps dev result : {e}")
        return {}


################################
# Actual list build management #
################################


def __build_app_dict(data) -> Optional[tuple[str, dict[str, Any]]]:
    (name, info), cache_path = data
    try:
        return name, build_app_dict(name, info, cache_path)
    except Exception as err:
        logging.error("[List builder] Error while updating %s: %s", name, err)
        return None


def build_base_catalog(
    catalog: dict[str, dict[str, Any]], cache_path: Path, nproc: int
):
    result_dict = {}

    with multiprocessing.Pool(processes=nproc) as pool:
        with logging_redirect_tqdm():
            tasks = pool.imap(
                __build_app_dict, zip(catalog.items(), repeat(cache_path))
            )

            for result in tqdm.tqdm(tasks, total=len(catalog.keys()), ascii=" ·#"):
                if result is not None:
                    name, info = result
                    result_dict[name] = info

    return result_dict


def write_catalog_v3(base_catalog, apps_path: Path, target_dir: Path) -> None:
    logos_dir = target_dir / "logos"
    logos_dir.mkdir(parents=True, exist_ok=True)

    def infos_for_v3(app_id: str, infos: Any) -> Any:
        # We remove the app install question and resources parts which aint
        # needed anymore by webadmin etc (or at least we think ;P)
        if "manifest" in infos and "install" in infos["manifest"]:
            del infos["manifest"]["install"]
        if "manifest" in infos and "resources" in infos["manifest"]:
            del infos["manifest"]["resources"]

        app_id = app_id.lower()
        logo_source = apps_path / "logos" / f"{app_id}.png"
        if logo_source.exists():
            logo_hash = (
                subprocess.check_output(["sha256sum", logo_source])
                .strip()
                .decode("utf-8")
                .split()[0]
            )
            shutil.copyfile(logo_source, logos_dir / f"{logo_hash}.png")
            # FIXME: implement something to cleanup old logo stuf in the builds/.../logos/ folder somehow
        else:
            logo_hash = None
        infos["logo_hash"] = logo_hash

        return infos

    full_catalog = {
        "apps": {app: infos_for_v3(app, info) for app, info in base_catalog.items()},
        "categories": categories_list(),
        "antifeatures": antifeatures_list(),
    }

    target_file = target_dir / "apps.json"
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.open("w", encoding="utf-8").write(
        json.dumps(full_catalog, sort_keys=True)
    )


def write_catalog_doc(base_catalog, target_dir: Path) -> None:
    def infos_for_doc_catalog(infos):
        level = infos.get("level")
        if not isinstance(level, int):
            level = -1
        return {
            "id": infos["id"],
            "category": infos["category"],
            "url": infos["git"]["url"],
            "name": infos["manifest"]["name"],
            "description": infos["manifest"]["description"],
            "state": infos["state"],
            "level": level,
            "broken": level <= 0,
            "good_quality": level >= 8,
            "bad_quality": level <= 5,
            "antifeatures": infos.get("antifeatures"),
            "potential_alternative_to": infos.get("potential_alternative_to", []),
        }

    result_dict_doc = {
        k: infos_for_doc_catalog(v)
        for k, v in base_catalog.items()
        if v["state"] == "working"
    }
    full_catalog = {"apps": result_dict_doc, "categories": categories_list()}

    target_file = target_dir / "apps.json"
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.open("w", encoding="utf-8").write(
        json.dumps(full_catalog, sort_keys=True)
    )


def build_app_dict(app, infos, cache_path: Path):
    # Make sure we have some cache
    this_app_cache = cache_path / app
    assert this_app_cache.exists(), f"No cache yet for {app}"

    repo = Repo(this_app_cache)

    # If added_date is not present, we are in a github action of the PR that adds it... so default to a bad value.
    infos["added_in_catalog"] = infos.get("added_date", 0)
    # int(commit_timestamps_for_this_app_in_catalog.split("\n")[0])

    infos["branch"] = infos.get("branch", "master")
    infos["revision"] = infos.get("revision", "HEAD")

    # If using head, find the most recent meaningful commit in logs
    if infos["revision"] == "HEAD":
        infos["revision"] = repo.head.commit.hexsha

    # Otherwise, validate commit exists
    else:
        try:
            _ = repo.commit(infos["revision"])
        except ValueError as err:
            raise RuntimeError(
                f"Revision ain't in history ? {infos['revision']}"
            ) from err

    # Find timestamp corresponding to that commit
    timestamp = repo.commit(infos["revision"]).committed_date

    alternative_branches = {}
    dev_ci_result_for_this_app = dev_ci_result_per_branch().get(app, {})
    for branch, result_infos in dev_ci_result_for_this_app.items():
        # For now, we only advertise testing.
        # We'll probably advertise another branch specifically for Nextcloud.
        # Maybe we should design a proper mechanism to declare somewhere what alternative branch exist
        if branch != "testing":
            continue
        try:
            ahead = not repo.is_ancestor(result_infos["commit"], infos["branch"])
        except Exception:
            # This will typically fail if the ref of the commit is unknown because it's only a single-branch checkout
            # ... BUT it could also be a super-old commit and we only have the last X commits in our checkout to optimize space hmpf
            ahead = True

        alternative_branches[branch] = {
            # NB : this is the latest commit tested by the dev CI, not the top of the branch
            "revision": result_infos["commit"],
            "level": result_infos["level"],
            "timestamp": result_infos["commit_timestamp"],
            "ahead": ahead,
            "version": result_infos["app_version"],
            "pr_url": result_infos["pr_url"],
        }

    # Build the dict with all the infos
    if (this_app_cache / "manifest.toml").exists():
        manifest = toml.load(
            (this_app_cache / "manifest.toml").open("r"), _dict=OrderedDict
        )
    else:
        manifest = json.load((this_app_cache / "manifest.json").open("r"))

    return {
        "id": manifest["id"],
        "git": {
            "branch": infos["branch"],
            "revision": infos["revision"],
            "url": infos["url"],
        },
        "alternative_branches": alternative_branches,
        "added_in_catalog": infos["added_in_catalog"],
        "lastUpdate": timestamp,
        "manifest": manifest,
        "state": infos["state"],
        "level": infos.get("level", "?"),
        "maintained": "package-not-maintained" not in infos.get("antifeatures", []),
        "high_quality": infos.get("high_quality", False),
        "featured": infos.get("featured", False),
        "category": infos.get("category", None),
        "subtags": infos.get("subtags", []),
        "potential_alternative_to": infos.get("potential_alternative_to", []),
        "antifeatures": list(
            set(
                list(manifest.get("antifeatures", {}).keys())
                + infos.get("antifeatures", [])
            )
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    get_apps_repo.add_args(parser)
    parser.add_argument(
        "target_dir",
        type=Path,
        nargs="?",
        help="The directory to write the catalogs to. Defaults to apps/builds/default",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=multiprocessing.cpu_count(),
        metavar="N",
        help="Allow N threads to run in parallel",
    )
    args = parser.parse_args()

    appslib.logging_sender.enable()

    apps_dir = get_apps_repo.from_args(args)
    cache_path = get_apps_repo.cache_path(args)
    cache_path.mkdir(exist_ok=True, parents=True)
    target_dir = args.target_dir or apps_dir / "builds" / "default"

    catalog = get_catalog(apps_dir)

    print("Retrieving all apps' information to build the catalog...")
    base_catalog = build_base_catalog(catalog, cache_path, args.jobs)

    print(f"Writing the catalogs to {target_dir}...")
    write_catalog_v3(base_catalog, apps_dir, target_dir / "v3")
    write_catalog_doc(base_catalog, target_dir / "doc_catalog")
    print("Done!")


if __name__ == "__main__":
    main()
