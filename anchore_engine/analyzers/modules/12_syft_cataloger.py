#!/usr/bin/env python3

import sys
import os
import re
import json
import tarfile

import anchore_engine.analyzers.utils


def main(config):
    imgname = config['imgid']
    print(f"We have an image! f{imgname}")

if __name__ == "__main__":

    try:
        config = anchore_engine.analyzers.utils.init_analyzer_cmdline(sys.argv, "syft_cataloger")
        print(config['dirs'])
    except Exception as err:
        # TODO: improve me
        print(str(err))
        sys.exit(1)

    main(config)