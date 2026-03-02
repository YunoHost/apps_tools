#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}")"  &> /dev/null && pwd)

: "${APPS_REPO_DIR:=.apps}"
: "${APPS_CACHE_DIR:=.apps_cache}"

update_venv() {
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    venv/bin/pip install -r requirements.txt > /dev/null
}

update_apps_repo() {
    if [ -d "$APPS_REPO_DIR" ]; then
        git -C "$APPS_REPO_DIR" pull
    else
        git clone https://github.com/YunoHost/apps.git "$APPS_REPO_DIR"
    fi
}

update_apps_cache() {
    venv/bin/python3 ./app_caches.py -d -l "$APPS_REPO_DIR" -c "$APPS_CACHE_DIR" -j20
}

git_pull_and_restart_services() {
    commit="$(git rev-parse HEAD)"

    if ! git pull &> /dev/null; then
        sendxmpppy "[apps-tools] Couldn't pull, maybe local changes are present?"
        exit 1
    fi

    if [[ "$(git rev-parse HEAD)" == "$commit" ]]; then
        return
    fi

    # Cron
    sed "s@__BASEDIR__@$SCRIPT_DIR@g" > /etc/cron.d/apps_tools < cron

    update_venv

    systemctl restart yunohost_app_webhooks
    sleep 3
    systemctl --quiet is-active yunohost_app_webhooks || sendxmpppy "[autoreadme] Uhoh, failed to (re)start the autoreadme service?"

}

# shellcheck disable=SC2034
rebuild_catalog_error_msg="[list_builder] Rebuilding the application list failed miserably!"
rebuild_catalog() {
    date
    update_apps_repo
    update_apps_cache
    venv/bin/python3 list_builder.py -l "$APPS_REPO_DIR" -c "$APPS_CACHE_DIR" ../catalog/default
}

# shellcheck disable=SC2034
autoupdate_app_sources_error_msg="[autoupdate_app_sources] App sources auto-update failed miserably!"
autoupdate_app_sources() {
    date
    update_apps_repo
    update_apps_cache
    venv/bin/python3 autoupdate_app_sources/autoupdate_app_sources.py \
        -l "$APPS_REPO_DIR" -c "$APPS_CACHE_DIR" --latest-commit-weekly --edit --commit --pr --paste -j1 --matrix-notification
}

# shellcheck disable=SC2034
update_app_levels_error_msg="[update_app_levels] Updating apps level failed miserably!"
update_app_levels() {
    date
    update_apps_repo
    update_apps_cache
    venv/bin/python3 update_app_levels/update_app_levels.py -r "git@github.com:YunoHost/apps.git" -c "$APPS_CACHE_DIR"
}

main() {
    cd "$SCRIPT_DIR"

    # Update self, then re-exec to prevent an issue with modified bash scripts
    if [[ -z "${APPS_TOOLS_UPDATED:-}" ]]; then
        git_pull_and_restart_services
        APPS_TOOLS_UPDATED=1 exec "$0" "$@"
    fi

    if ! "$@"; then
        error_msg_var="${1}_error_msg"
        sendxmpppy "${!error_msg_var}"
    fi
}

main "$@"
