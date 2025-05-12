#!/usr/bin/env python3

import tempfile
import shutil
import subprocess

from pathlib import Path

TEST_DIRECTORY = Path(__file__).resolve().parent

TEST_APP_NAME = "gotosocial_ynh"
TEST_APP_REPO = "https://github.com/yunohost-apps/gotosocial_ynh"
TEST_APP_COMMIT_ID = "8f788213b363a46a5b6faa8f844d86d4adac9446"


def test_running_make_readme():
    with tempfile.TemporaryDirectory() as tempdir:
        test_app_dir = Path(tempdir) / TEST_APP_NAME

        cmd = ["git", "clone", "-q", TEST_APP_REPO, test_app_dir]
        subprocess.check_call(cmd)

        cmd = ["git", "checkout", "-q", TEST_APP_COMMIT_ID]
        subprocess.check_call(cmd, cwd=test_app_dir)

        # Now run test...
        cmd = [TEST_DIRECTORY.parent / "make_readme.py", test_app_dir]
        subprocess.check_call(cmd)

        test_content = (TEST_DIRECTORY / "README.md").read_text()
        result_content = (test_app_dir / "README.md").read_text()
        if test_content != result_content:
            shutil.copyfile(
                test_app_dir / "README.md", TEST_DIRECTORY / "README_failed.md"
            )

        assert (
            test_content.strip() == result_content.strip()
        ), f"Failed readme was copied to {TEST_DIRECTORY / 'README_failed.md'}"


if __name__ == "__main__":
    test_running_make_readme()
