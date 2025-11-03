"""Build server distribution"""

import os
import sys
from setuptools import setup

PACKAGE_NAME = os.getenv("PACKAGE_NAME")
if PACKAGE_NAME is None:
    print("Please provide PACKAGE_NAME as env variable.")
    sys.exit(1)

# Passed as env variable.
VERSION = os.getenv("VERSION")
if VERSION is None:
    print("Please provide VERSION as env variable.")
    sys.exit(1)

MODEL_VERSION = VERSION.split("+")[0]


def get_reqs_from_file(filepath: str, recursive: bool):
    reqs = []
    with open(filepath, "r", encoding="utf-8") as fp:
        for line in fp:
            if not line.startswith("-"):
                reqs.append(line)
            elif recursive and line.startswith("-r"):
                recursive_filepath = line.split()[1]
                reqs.extend(get_reqs_from_file(recursive_filepath, True))
    return reqs


install_requires = []
install_requires.extend(get_reqs_from_file(os.path.join("artifacts", "requirements.txt"), True))

setup(
    name=PACKAGE_NAME,
    version=VERSION,
    python_requires=">=3.10",
    author="Keysight",
    author_email="harsh.sikhwals@keysight.com",
    url="https://keysight.com",
    packages=[PACKAGE_NAME],  # type: ignore
    include_package_data=True,
    package_data={PACKAGE_NAME: ["openapi.yaml"]},
    install_requires=install_requires,
    dependency_links=[],
)
