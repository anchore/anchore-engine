import json
import os
import shlex

import anchore_engine
from anchore_engine.utils import run_check

DEFAULT_TMP_DIR = "/analysis_scratch"


def get_tmp_dir_from_config():
    localconfig = anchore_engine.configuration.localconfig.get_config()
    return localconfig.get("tmp_dir", DEFAULT_TMP_DIR)


def run_syft(image):
    proc_env = os.environ.copy()
    tmp_dir = get_tmp_dir_from_config()

    syft_env = {
        "SYFT_CHECK_FOR_APP_UPDATE": "0",
        "SYFT_LOG_STRUCTURED": "1",
        "TMP_DIR": tmp_dir,
    }

    proc_env.update(syft_env)

    cmd = "syft -vv -o json oci-dir:{image}".format(image=image)

    stdout, _ = run_check(shlex.split(cmd), env=proc_env, log_level="spew")

    return json.loads(stdout)
