#!/usr/bin/env python3

import sys
import tomlkit
import hashlib
import argparse
import hmac
from functools import cache
import tempfile
import aiohttp
import logging
from pathlib import Path
import re
import requests

from typing import Optional
from git import Actor, Repo, GitCommandError
from sanic import HTTPResponse, Request, Sanic, response

# add apps/tools to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from appslib import get_apps_repo
from readme_generator.make_readme import generate_READMEs

TOOLS_DIR = Path(__file__).resolve().parent.parent

DEBUG = False
UNSAFE = False

APP = Sanic(__name__)


@cache
def github_webhook_secret() -> str:
    return (
        (TOOLS_DIR / ".github_webhook_secret")
        .open("r", encoding="utf-8")
        .read()
        .strip()
    )


@cache
def github_login() -> str:
    return (TOOLS_DIR / ".github_login").open("r", encoding="utf-8").read().strip()


@cache
def github_token() -> str:
    return (TOOLS_DIR / ".github_token").open("r", encoding="utf-8").read().strip()


@cache
def github_token_membership() -> str:
    return (
        (TOOLS_DIR / ".github_token_membership")
        .open("r", encoding="utf-8")
        .read()
        .strip()
    )


@cache
def github_token_invitations() -> str:
    return (
        (TOOLS_DIR / ".github_token_invitations")
        .open("r", encoding="utf-8")
        .read()
        .strip()
    )


@APP.route("/github", methods=["GET"])
async def github_get(request: Request) -> HTTPResponse:
    return response.text(
        "You aren't supposed to go on this page using a browser, it's for webhooks push instead."
    )


@APP.route("/github", methods=["POST"])
async def github_post(request: Request) -> HTTPResponse:
    if UNSAFE:
        logging.warning("Unsafe webhook!")
    elif signatures_reply := check_webhook_signatures(request):
        return signatures_reply

    event = request.headers.get("X-Github-Event")
    if event == "push":
        return on_push(request)

    if event == "issue_comment":
        infos = request.json
        valid_pr_comment = (
            infos["action"] == "created"
            and infos["issue"]["state"] == "open"
            and "pull_request" in infos["issue"]
        )
        pr_infos = await get_pr_infos(request)

        if valid_pr_comment and pr_infos:
            return on_pr_comment(request, pr_infos)
        else:
            return response.empty()

    return response.json({"error": f"Unknown event '{event}'"}, 422)


async def get_pr_infos(request: Request) -> dict:
    pr_infos_url = request.json["issue"].get("pull_request", {}).get("url")
    if not pr_infos_url:
        return {}
    async with aiohttp.ClientSession() as session:
        async with session.get(pr_infos_url) as resp:
            pr_infos = await resp.json()
    return pr_infos


def check_webhook_signatures(request: Request) -> Optional[HTTPResponse]:
    header_signature = request.headers.get("X-Hub-Signature")
    if header_signature is None:
        logging.error("no header X-Hub-Signature")
        return response.json({"error": "No X-Hub-Signature"}, 403)

    sha_name, signature = header_signature.split("=")
    if sha_name != "sha1":
        logging.error("signing algo isn't sha1, it's '%s'" % sha_name)
        return response.json({"error": "Signing algorightm is not sha1 ?!"}, 501)

    # HMAC requires the key to be bytes, but data is string
    mac = hmac.new(
        github_webhook_secret().encode(), msg=request.body, digestmod=hashlib.sha1
    )

    if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
        return response.json({"error": "Bad signature ?!"}, 403)
    return None


def on_push(request: Request) -> HTTPResponse:
    data = request.json
    repository = data["repository"]["full_name"]
    branch = data["ref"].split("/", 2)[2]

    if not repository.startswith("YunoHost-Apps/"):
        return response.empty()

    logging.info(f"{repository} -> branch '{branch}'")

    need_push = False
    with tempfile.TemporaryDirectory() as folder_str:
        folder = Path(folder_str)
        repo = Repo.clone_from(
            f"https://{github_login()}:{github_token()}@github.com/{repository}",
            to_path=folder,
        )

        # First rebase the testing branch if possible
        if branch in ["main", "master", "testing"]:
            result = git_repo_rebase_testing_fast_forward(repo)
            need_push = need_push or result

        repo.git.checkout(branch)

        result = False
        if not "no_readme" in repo.head.commit.message:
            result = generate_and_commit_readmes(repo)

        need_push = need_push or result

        if not need_push:
            logging.debug("nothing to do")
            return response.text("nothing to do")

        logging.debug(f"Pushing {repository}")
        repo.remote().push(quiet=False, all=True)

    return response.text("ok")


def on_pr_comment(request: Request, pr_infos: dict) -> HTTPResponse:
    fullbody = request.json["comment"]["body"]
    body = fullbody.strip()[:100].lower()

    # Check the comment contains proper keyword trigger

    BUMP_REV_COMMANDS = ["!bump", "!new_revision", "!newrevision"]
    if any(trigger.lower() in body for trigger in BUMP_REV_COMMANDS):
        return bump_revision(request, pr_infos)

    CHANGELOG_COMMANDS = ["!changelog", "!pre_upgrade", "!preupgrade"]
    if any(trigger.lower() in body for trigger in CHANGELOG_COMMANDS):
        changelog = ""
        for command in CHANGELOG_COMMANDS:
            try:
                changelog = (
                    re.search(f"{command}\s*(.*)", fullbody, re.DOTALL)
                    .group(1)
                    .rstrip()
                )
            except:
                pass
        return add_changelog(request, pr_infos, changelog)

    REJECT_WISHLIST_COMMANDS = ["!reject", "!nope"]
    if any(trigger.lower() in body for trigger in REJECT_WISHLIST_COMMANDS):
        reason = ""
        for command in REJECT_WISHLIST_COMMANDS:
            try:
                reason = re.search(f"{command} (.*)", fullbody).group(1).rstrip()
            except:
                pass
        return reject_wishlist(request, pr_infos, reason)

    INVITE_COMMANDS = ["!invite", "!allezviensonestbien"]
    if any(trigger.lower() in body for trigger in INVITE_COMMANDS):
        user = ""
        for command in INVITE_COMMANDS:
            try:
                invitee = re.search(f"{command} @?(\S+)", fullbody).group(1).rstrip()
            except:
                pass
        return invite(request, pr_infos, invitee)

    return response.empty()


def bump_revision(request: Request, pr_infos: dict) -> HTTPResponse:
    data = request.json
    repository = data["repository"]["full_name"]
    branch = pr_infos["head"]["ref"]

    if not repository.startswith("YunoHost-Apps/"):
        return response.empty()

    logging.info(f"Will bump revision on {repository} branch {branch}...")
    with tempfile.TemporaryDirectory() as folder_str:
        folder = Path(folder_str)
        repo = Repo.clone_from(
            f"https://{github_login()}:{github_token()}@github.com/{repository}",
            to_path=folder,
        )
        repo.git.checkout(branch)

        manifest_file = folder / "manifest.toml"
        manifest = tomlkit.load(manifest_file.open("r", encoding="utf-8"))
        version, revision = manifest["version"].split("~ynh")
        revision = str(int(revision) + 1)
        manifest["version"] = "~ynh".join([version, revision])
        tomlkit.dump(manifest, manifest_file.open("w", encoding="utf-8"))

        repo.git.add("manifest.toml")
        repo.index.commit(
            "Bump package revision",
            author=Actor("yunohost-bot", "yunohost@yunohost.org"),
        )

        generate_and_commit_readmes(repo)

        logging.debug(f"Pushing {repository}")
        repo.remote().push(quiet=False, all=True)
        return response.text("ok")


def add_changelog(request: Request, pr_infos: dict, changelog=None) -> HTTPResponse:
    data = request.json
    repository = data["repository"]["full_name"]
    branch = pr_infos["head"]["ref"]

    if not repository.startswith("YunoHost-Apps/"):
        return response.empty()

    logging.info(f"Will add changelog on {repository} branch {branch}...")
    with tempfile.TemporaryDirectory() as folder_str:
        folder = Path(folder_str)
        repo = Repo.clone_from(
            f"https://{github_login()}:{github_token()}@github.com/{repository}",
            to_path=folder,
        )
        repo.git.checkout(branch)

        manifest_file = folder / "manifest.toml"
        manifest = tomlkit.load(manifest_file.open("r", encoding="utf-8"))
        version = manifest["version"]

        file = Path(f"{folder}/doc/PRE_UPGRADE.d/{version}.md")
        file.parent.mkdir(parents=True, exist_ok=True)

        with open(file, "a") as f:
            f.write(f"{changelog}")

        repo.git.add(file)
        repo.index.commit(
            f"Add pre_upgrade message for {version}",
            author=Actor("yunohost-bot", "yunohost@yunohost.org"),
        )

        logging.debug(f"Pushing {repository}")
        repo.remote().push(quiet=False, all=True)
        return response.text("ok")


def reject_wishlist(request: Request, pr_infos: dict, reason=None) -> HTTPResponse:
    data = request.json
    repository = data["repository"]["full_name"]
    branch = pr_infos["head"]["ref"]
    pr_number = pr_infos["number"]

    if repository != "YunoHost/apps" or not branch.startswith("add-to-wishlist"):
        return response.empty()

    can_reject = False
    if data["comment"]["author_association"] == "OWNER":
        can_reject = True
        logging.info(
            f"User {user} is an owner of the YunoHost org and can thus reject apps from the wishlist"
        )

    with requests.Session() as s:
        s.headers.update({"Authorization": f"token {github_token_membership()}"})
        r = s.get(
            f"https://api.github.com/orgs/YunoHost/teams/apps/memberships/{user}"
        )
        if r.status_code == 200:
            can_reject = True
            logging.info(
                f"User {user} is in the Apps team"
            )
        elif r.status_code == 404:
            logging.info(
                f"User {user} is not the Apps team"
            )
        else:
            logging.info(
                f"Checking for {user} belonging in the Apps team failed with code {r.status_code}"
            )

    with requests.Session() as s:
        s.headers.update({"Authorization": f"token {github_token_invitations()}"})
        r = s.get(
            f"https://api.github.com/orgs/YunoHost-Apps/teams/regular-contributors/memberships/{user}"
        )
        if r.status_code == 200:
            can_reject = True
            logging.info(
                f"User {user} is a Regular Contributor"
            )
        elif r.status_code == 404:
            logging.info(
                f"User {user} is not a Regular Contributor"
            )
        else:
            logging.info(
                f"Checking for {user} belonging in the Regular Contributors team failed with code {r.status_code}"
            )

    if not can_reject:
        logging.info(
            f"User {user} is not allowed to reject apps from the wishlist"
        )
        with requests.Session() as s:
            comment_id = data["comment"]["id"]
            s.headers.update({"Authorization": f"token {github_token()}"})
            r = s.post(
                f"https://api.github.com/repos/{repository}/issues/comments/{comment_id}/reactions",
                json='{"content": "-1"}'
            )
        return response.empty()

    logging.info(
        f"Will put the suggested app in the rejected list on {repository} branch {branch}..."
    )
    with tempfile.TemporaryDirectory() as folder_str:
        folder = Path(folder_str)
        repo = Repo.clone_from(
            f"https://{github_login()}:{github_token()}@github.com/{repository}",
            to_path=folder,
        )
        repo.git.checkout(branch)

        rejectedlist_file = folder / "rejectedlist.toml"
        rejectedlist = tomlkit.load(rejectedlist_file.open("r", encoding="utf-8"))

        wishlist_file = folder / "wishlist.toml"
        wishlist = tomlkit.load(wishlist_file.open("r", encoding="utf-8"))

        suggestedapp_slug = branch.replace("add-to-wishlist-", "")
        suggestedapp = {suggestedapp_slug: wishlist[suggestedapp_slug]}
        suggestedapp[suggestedapp_slug]["rejection_pr"] = pr_infos["html_url"]
        suggestedapp[suggestedapp_slug]["reason"] = reason

        wishlist.pop(suggestedapp_slug)
        rejectedlist.update(suggestedapp)

        tomlkit.dump(rejectedlist, rejectedlist_file.open("w", encoding="utf-8"))
        tomlkit.dump(wishlist, wishlist_file.open("w", encoding="utf-8"))

        repo.git.add("rejectedlist.toml")
        repo.git.add("wishlist.toml")

        suggestedapp_name = suggestedapp[suggestedapp_slug]["name"]
        repo.index.commit(
            f"Reject {suggestedapp_name} from catalog",
            author=Actor("yunohost-bot", "yunohost@yunohost.org"),
        )

        logging.debug(f"Pushing {repository}")
        repo.remote().push(quiet=False, all=True, force=True)

        new_pr_title = {"title": f"Add {suggestedapp_name} to rejection list"}
        with requests.Session() as s:
            s.headers.update({"Authorization": f"token {github_token()}"})
            r = s.post(
                f"https://api.github.com/repos/{repository}/pulls/{pr_number}",
                json=new_pr_title,
            )
            if r.status_code != 200:
                logging.info(
                    f"PR #{pr_number} renaming failed with code {r.status_code}"
                )

        return response.text("ok")


def invite(request: Request, pr_infos: dict, invitee=None) -> HTTPResponse:
    data = request.json
    repository = data["repository"]["full_name"]
    branch = pr_infos["head"]["ref"]
    user = data["comment"]["user"]["login"]

    if (
        repository != "YunoHost/apps" and not repository.startswith("YunoHost-Apps/")
    ) or user is None:
        return response.empty()

    can_invite = False
    if data["comment"]["author_association"] == "OWNER":
        can_invite = True
        logging.info(
            f"User {user} is an owner of the YunoHost org and can thus invite people to the YunoHost-Apps org"
        )
    else:
        with requests.Session() as s:
            s.headers.update({"Authorization": f"token {github_token_membership()}"})
            r = s.get(
                f"https://api.github.com/orgs/YunoHost/teams/apps/memberships/{user}"
            )
            if r.status_code == 200:
                can_invite = True
                logging.info(
                    f"User {user} is in the Apps team and can invite people to the YunoHost-Apps org"
                )
            else:
                logging.info(
                    f"Checking for {user} belonging in the Apps team failed with code {r.status_code}"
                )

    if can_invite:
        with requests.Session() as s:
            invitee_id = s.get(f"https://api.github.com/users/{invitee}").json()["id"]
            s.headers.update(
                {
                    "Authorization": f"token {github_token_invitations()}",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "Accept": "application/vnd.github+json",
                }
            )
            s.headers.update({"Authorization": f"token {github_token_invitations()}"})
            r = s.post(
                f"https://api.github.com/orgs/YunoHost-Apps/invitations",
                json={"invitee_id": invitee_id},
            )
            if r.status_code == 201:
                logging.info(
                    f"User {invitee} has been invited to the YunoHost-Apps org"
                )
                s.headers.update({"Authorization": f"token {github_token()}"})
                r = s.post(
                    data["issue"]["comments_url"],
                    json={
                        "body": f"@{invitee}, you have just been invited to the YunoHost-Apps organization.\nWe suggest that you transfer your repository in the org so that you can take advantage of the automated CI tests and other packagers' help:\n  1. check your notifications and accept the invitation.\n  2. transfer your repository to the YunoHost-Apps organization.\n  3. open a PR from the testing branch to the main branch of your repository\n  4. add your commits and open a pull request.\n  5. trigger the CI with `!testme` in a comment in that PR.\n\nDo not forget to update your repository URL in the catalog.\n\nYou can find more information on packaging in our [documentation](https://doc.yunohost.org/dev/packaging/)"
                    },
                )
            else:
                logging.info(
                    f"Inviting {invitee} (id: {invitee_id}) has failed with code {r.status_code}"
                )
            return response.empty(status=r.status_code)

    return response.empty()


def generate_and_commit_readmes(repo: Repo) -> bool:
    assert repo.working_tree_dir is not None
    generate_READMEs(Path(repo.working_tree_dir))

    for change in repo.index.diff(None):
        repo.git.add(change.b_path)

    diff_empty = len(repo.index.diff("HEAD")) == 0
    if diff_empty:
        return False

    repo.index.commit(
        "Auto-update READMEs", author=Actor("yunohost-bot", "yunohost@yunohost.org")
    )
    return True


def git_repo_rebase_testing_fast_forward(repo: Repo) -> bool:
    try:
        repo.git.checkout("testing")
    except GitCommandError:
        return False

    if "main" in repo.heads and repo.is_ancestor("testing", "main"):
        repo.git.merge("main", ff_only=True)
        return True
    elif "master" in repo.heads and repo.is_ancestor("testing", "master"):
        repo.git.merge("master", ff_only=True)
        return True

    return False


def main() -> None:
    parser = argparse.ArgumentParser()
    get_apps_repo.add_args(parser)
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument(
        "-u",
        "--unsafe",
        action="store_true",
        help="Disable Github signature checks on webhooks, for debug only.",
    )
    args = parser.parse_args()

    global APPS_REPO
    APPS_REPO = get_apps_repo.from_args(args)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    global DEBUG, UNSAFE
    DEBUG = args.debug
    UNSAFE = args.unsafe

    APP.run(host="127.0.0.1", port=8123, debug=args.debug)


if __name__ == "__main__":
    main()
