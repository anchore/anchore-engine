#!/bin/bash

python setup.py bdist_rpm --requires="python python-setuptools python2-clint PyYAML python-requests python-click python-prettytable python-docker-py dpkg rpm-python python-sqlalchemy python2-pg8000 python-flask python-twisted-core python-twisted-web python2-attrs pyOpenSSL python-jsonschema" --build-requires="python python-setuptools" --release="0"
python setup.py clean --all
