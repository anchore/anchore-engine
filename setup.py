#!/usr/bin/python
import os
import re

from setuptools import find_packages, setup

from anchore_engine import version

package_name = "anchore_engine"

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

setup(
    name="anchore_engine",
    author="Anchore Inc.",
    author_email="dev@anchore.com",
    license="Apache License 2.0",
    description="Anchore Engine",
    long_description=open("README.md").read(),
    url="http://www.anchore.com",
    python_requires="==3.8.*",
    packages=find_packages(exclude=["test", "test.*"]) + ["twisted.plugins"],
    version=version.version,
    include_package_data=True,
    install_requires=requirements,
    scripts=[],
    entry_points="""
    [console_scripts]
    anchore-manager=anchore_manager.cli:main_entry
    """,
)
