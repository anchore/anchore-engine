#!/usr/bin/python
import os
import re

from setuptools import find_packages, setup

from anchore_engine import version

version = version.version
package_name = "anchore_engine"
description = "Anchore Engine"
long_description = open("README.md").read()
url = "http://www.anchore.com"

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

# find all the swaggers
swaggers = []
for root, dirnames, filenames in os.walk("./" + package_name):
    if "swagger.yaml" in filenames:
        theswaggerdir = re.sub(re.escape("./" + package_name + "/"), "", root)
        swaggers.append("/".join([theswaggerdir, "swagger.yaml"]))

package_data = {
    package_name: [
        "conf/*",
        "conf/bundles/*",
        "analyzers/modules/*",
    ]
    + swaggers,
    "twisted": ["plugins/*"],
}

data_files = []
# scripts = ['scripts/anchore-engine']
scripts = []
packages = find_packages(exclude=["test", "test.*"])
packages.append("twisted.plugins")
setup(
    name="anchore_engine",
    author="Anchore Inc.",
    author_email="dev@anchore.com",
    license="Apache License 2.0",
    description=description,
    long_description=long_description,
    url=url,
    python_requires="==3.8.*",
    packages=packages,
    version=version,
    data_files=data_files,
    include_package_data=True,
    package_data=package_data,
    install_requires=requirements,
    scripts=scripts,
    entry_points="""
    [console_scripts]
    anchore-manager=anchore_manager.cli:main_entry
    """,
)
