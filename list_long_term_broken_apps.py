#!/usr/bin/env python3

import json
import subprocess
import tomllib
from datetime import datetime
from typing import Any, Generator

CATALOG_REPO_CLONE = "../apps/"


def git(cmd: list[str]) -> str:
    return (
        subprocess.check_output(["git", "-C", CATALOG_REPO_CLONE] + cmd)
        .decode("utf-8")
        .strip()
    )


def _time_points_until_today() -> Generator[datetime, None, None]:
    year = 2022
    month = 1
    day = 1
    today = datetime.today()
    date = datetime(year, month, day)

    while date < today:
        yield date

        day += 14
        if day > 15:
            day = 1
            month += 1

        if month > 12:
            month = 1
            year += 1

        date = datetime(year, month, day)


def get_history(
    N: int,
) -> Generator[tuple[datetime, dict[str, Any]], None, None]:
    for t in list(_time_points_until_today())[(-1 * N) :]:
        # Fetch apps list content at this date
        commit = git(
            [
                "rev-list",
                "-1",
                "--before='%s'" % t.strftime("%b %d %Y"),
                "main",
            ]
        )
        raw_catalog_at_this_date = git(["show", f"{commit}:apps.toml"])

        try:
            catalog_at_this_date = tomllib.loads(raw_catalog_at_this_date)
        # This can happen in stupid cases where there was a temporary syntax error in the json..
        except json.decoder.JSONDecodeError:
            print(
                "Failed to parse apps.toml history for at commit %s / %s ... ignoring "
                % (commit, t)
            )
            continue
        yield (t, catalog_at_this_date)


# We'll check the history for last 12 months (*2 points per month)
N = 12 * 2 * 2
history = list(get_history(N))

current_catalog = tomllib.loads(open(str(CATALOG_REPO_CLONE) + "/apps.toml").read())

currently_broken_apps = [
    app
    for app, infos in current_catalog.items()
    if infos["state"] == "working" and infos.get("level") == 0
]

app_last_time_non_broken = []

for app in currently_broken_apps:
    last_time_non_broken = None
    previous_non_broken_level = None
    for t, catalog in reversed(history):
        if app not in catalog or catalog[app]["state"] != "working":
            break
        level = catalog[app].get("level")
        if level != 0:
            last_time_non_broken = t
            previous_non_broken_level = level
            break

    app_last_time_non_broken.append(
        (last_time_non_broken, app, previous_non_broken_level)
    )

sorted_entries = sorted(
    app_last_time_non_broken,
    key=lambda entry: entry[0] or datetime(1970, 1, 1),
    reverse=True,
)
for last_time_non_broken, app, previous_non_broken_level in sorted_entries:
    if previous_non_broken_level:
        print(
            f"{app} was level {previous_non_broken_level} back to "
            + last_time_non_broken.date().strftime("%b %d %Y")
        )
    else:
        print(f"{app} : can't find last time it was not broken")
