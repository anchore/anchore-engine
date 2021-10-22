import json
import os
import shlex

from anchore_engine.utils import run_check


def run_syft(unpackdir, image):
    proc_env = os.environ.copy()

    syft_env = {
        "SYFT_CHECK_FOR_APP_UPDATE": "0",
        "SYFT_LOG_STRUCTURED": "1",
        "TMPDIR": unpackdir,
    }

    proc_env.update(syft_env)

    cmd = "syft -vv -o json oci-dir:{image}".format(image=image)

    stdout, _ = run_check(shlex.split(cmd), env=proc_env, log_level="spew")

    return json.loads(stdout)
