#!/usr/bin/env python3

import argparse
import os
import re


def cleanup():

    techno_versions = {}

    if os.path.exists("scripts/_common.sh"):
        common_content = open("scripts/_common.sh").read()
        for techno in ["nodejs", "ruby", "go", "composer"]:
            matches = re.findall(f"\n *{techno}_version=['\"]?([0-9\\.]+)['\"]?", common_content.lower())
            if not matches:
                continue
            if len(matches) > 1:
                print(f"Uhoh ? Found multi version for {techno} ...")
                continue
            v = matches[0]
            if techno == "nodejs" and "." in v:
                v = v.split(".")[0]
            techno_versions[techno] = v

    removememaybes = [
        # nodejs
        "nodejs_version=",
        "NODEJS_VERSION=",
        "ynh_nodejs_remove",
        "ynh_remove_nodejs",
        "ynh_use_nodejs",
        "ynh_exec_warn_less ynh_install_nodejs",
        "ynh_hide_warnings ynh_nodejs_install",
        "ynh_install_nodejs",
        "ynh_nodejs_install",
        # ruby
        "ruby_version=",
        "ynh_ruby_install",
        "ynh_exec_warn_less ynh_install_ruby",
        "ynh_hide_warnings ynh_ruby_install",
        "ynh_install_ruby",
        "ynh_ruby_remove",
        "ynh_remove_ruby",
        "ynh_ruby_load_path",
        "ynh_use_ruby",
        # go
        "go_version=",
        "ynh_exec_warn_less ynh_install_go",
        "ynh_hide_warnings ynh_go_install",
        "ynh_install_go",
        "ynh_go_install",
        "ynh_go_remove",
        "ynh_remove_go",
        "ynh_use_go",
        # composer
        "composer_version=",
        "ynh_exec_warn_less ynh_install_composer",
        "ynh_hide_warnings ynh_composer_install",
        "ynh_install_composer",
        "ynh_composer_install",
    ]

    for s in [
        "_common.sh",
        "install",
        "remove",
        "upgrade",
        "backup",
        "restore",
        "change_url",
        "config",
    ]:

        script = f"scripts/{s}"

        if not os.path.exists(script):
            continue

        content = open(script).read()

        for remove in removememaybes:
            content = content.replace(remove, r"#REMOVEME? " + remove)

        open(script, "w").write(content)

    if techno_versions:
        raw_manifest = open("manifest.toml", "r").read()
        raw_manifest = re.sub(
            r'yunohost = ">= .*"', 'yunohost = ">= 12.1.17"', raw_manifest
        )
        for techno, version in techno_versions.items():
            if f"[resources.{techno}]" in raw_manifest:
                continue
            raw_manifest += f"""
    [resources.{techno}]
    version = "{version}"
"""

        open("manifest.toml", "w").write(raw_manifest)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Attempt to automatically convert calls to legacy nodejs/ruby/go/composer install/remove helpers to manifest resources"
    )
    parser.add_argument("app_path", help="Path to the app to convert")

    args = parser.parse_args()

    if not os.path.exists(args.app_path + "/manifest.toml"):
        raise Exception("There is no manifest.toml. Is this really an app directory ?")

    os.chdir(args.app_path)

    cleanup()
