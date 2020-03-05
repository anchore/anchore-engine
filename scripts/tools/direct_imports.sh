#!/bin/bash

# Requires findimports from pip
#pip install -y findimports

findimports anchore_engine anchore_manager twisted | grep -v "anchore\|:" | cut -f 1 -d '.' | sort | uniq  > imports
findimports test | grep -v "anchore\|:" | cut -f 1 -d '.' | sort | uniq  > test_imports
