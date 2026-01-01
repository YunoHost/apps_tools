import os
import argparse
from glob import glob
import re

PROXY_HEADERS_TO_PATCH = [
    "Host",
    "X-Real-IP",
    "X-Scheme",
    "X-Forwarded-For",
    "X-Forwarded-Proto",
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Ssl",
    "X-Forwarded-Server",
    "Ynh-User",
    "Ynh-User-Email",
    "Ynh-User-Fullname",
    "X-Forwarded-User",
    "REMOTE_USER",
    "Connection",
    "Upgrade",
    "Authorization",
]

FASTCGI_PARAMS_TO_PATCH = [
    "HTTPS",
    "REMOTE_USER",
    "PATH_INFO",
    "SCRIPT_FILENAME",
]

PROXY_HEADERS_TO_PATCH_REGEX = re.compile(
    rf"(^\s+proxy_set_header\s+({'|'.join(PROXY_HEADERS_TO_PATCH)})\s+\S+\s*;.*$)",
    re.MULTILINE,
)
FASTCGI_PARAMS_TO_PATCH_REGEX = re.compile(
    rf"(^\s+fastcgi_param\s+({'|'.join(FASTCGI_PARAMS_TO_PATCH)})\s+\S+\s*;.*$)",
    re.MULTILINE,
)

OTHER_PATTERNS_TO_REMOVE = [
    r"proxy_http_version\s+1.1;",
    r"# Include SSOWAT user panel.",
    r"include\s+conf.d/yunohost_panel.conf.inc;",
    r"fastcgi_index\s+index.php;",
    r"fastcgi_split_path_info.*;",
    r"include\s+proxy_params;",
    r"include\s+fastcgi_params;",
]
OTHER_PATTERNS_TO_REMOVE_REGEXES = [
    re.compile(rf"(^\s*{p}\s*$)", re.MULTILINE) for p in OTHER_PATTERNS_TO_REMOVE
]

REVERSE_PROXY_STATEMENTS = r"(^(\s*)(fastcgi_pass|proxy_pass)\s+.*;\s*$)"
REVERSE_PROXY_STATEMENTS_REGEX = re.compile(REVERSE_PROXY_STATEMENTS, re.MULTILINE)


def patch(content: str, with_auth: bool) -> str:
    for regex in [
        PROXY_HEADERS_TO_PATCH_REGEX,
        FASTCGI_PARAMS_TO_PATCH_REGEX,
    ] + OTHER_PATTERNS_TO_REMOVE_REGEXES:
        for match in regex.findall(content):
            if isinstance(match, tuple):
                match = match[0]
            if (
                "proxy_set_header" in match
                and "Connection" in match
                and "keep-alive" in match
            ):
                # Not sure about replacing "Connection keep-alive" which is used by some apps (grafana, kiwix, netdata, piped),
                # the new default value is supposed to be $connection_upgrade corresponding to "upgrade" or empty string (i think?)
                continue
            if (
                "fastcgi_split_path_info" in match
                and r"^(.+?\.php)(/.*)$;" not in match
            ):
                # Some apps have a different regex than the default one from the new fastcgi include
                # though it's unclear why...
                continue
            content = content.replace("\n" + match, "")

    # set is used to make sure we get unique matches
    reverse_proxy_matches = REVERSE_PROXY_STATEMENTS_REGEX.findall(content)
    reverse_proxy_matches = set((m.strip(), i, t) for m, i, t in reverse_proxy_matches)

    suffix = "no_auth" if not with_auth else "with_auth"
    for match, indent, type_ in reverse_proxy_matches:
        match_with_indent = f"\n{indent}{match}"
        if type_ == "fastcgi_pass":
            content = content.replace(
                match_with_indent,
                match_with_indent + f"\n{indent}include fastcgi_params_{suffix};",
            )
        elif type_ == "proxy_pass":
            if not any(
                k in match_with_indent for k in ["127.0.0.1", "localhost", "unix:"]
            ):
                content = content.replace(
                    match_with_indent,
                    match_with_indent + f"\n{indent}include proxy_params_no_auth;",
                )
            else:
                content = content.replace(
                    match_with_indent,
                    match_with_indent + f"\n{indent}include proxy_params_{suffix};",
                )
        else:
            raise Exception(f"Uhoh, what's {type_}?")

    return content


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Patch nginx configurations to standardize proxy_set_headers and fastcgi_params"
    )
    parser.add_argument("app_path", help="Path to the app to convert")

    args = parser.parse_args()

    if not os.path.exists(args.app_path + "/manifest.toml"):
        raise Exception("There is no manifest.toml. Is this really an app directory ?")

    os.chdir(args.app_path)

    raw_manifest = open("manifest.toml", "r").read()
    sso_enabled = "sso = true" in raw_manifest

    any_change = False
    for file in glob("conf/nginx*.conf"):
        content = open(file).read()
        if "fastcgi_pass" not in content and "proxy_pass" not in content:
            continue
        any_change = True
        patched_content = patch(content, sso_enabled)
        open(file, "w").write(patched_content)

    if any_change:
        raw_manifest = re.sub(
            r'yunohost = ">= .*"', 'yunohost = ">= 12.1.38"', raw_manifest
        )
        open("manifest.toml", "w").write(raw_manifest)
    else:
        print("(Nothing patched)")
