#! /usr/bin/env python3

import sys
import argparse
from pathlib import Path

import toml
from jinja2 import Environment, FileSystemLoader

# add apps/tools to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

README_GEN_DIR = Path(__file__).resolve().parent


def generate_READMEs(app_path: Path):
    if not app_path.exists():
        raise Exception("App path provided doesn't exists ?!")

    manifest = toml.load(open(app_path / "manifest.toml"))

    env = Environment(
        loader=FileSystemLoader(README_GEN_DIR),
    )
    template = env.get_template("README.md.j2")

    out: str = template.render(manifest=manifest)
    (app_path / "README.md").write_text(out)

    # Delete legacy READMEs
    for legacy_README in app_path.glob("README_*.md"):
        legacy_README.unlink()
    if (app_path / "ALL_README.md").exists():
        (app_path / "ALL_README.md").unlink()


def main():
    parser = argparse.ArgumentParser(
        description="Automatically (re)generate README for apps"
    )
    parser.add_argument(
        "app_path", type=Path, help="Path to the app to generate/update READMEs for"
    )
    args = parser.parse_args()

    generate_READMEs(args.app_path)


if __name__ == "__main__":
    main()
