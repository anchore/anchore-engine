"""
This script is a wrapper to allow the code in
anchore_engine.clients.localanchore_standalone work without the need for
a running anchore-engine service(s). More specifically, it sets everything up
needed for the `analyze_image()` function, and it does so *for testing
purposes*.

By default, it uses the `centos:centos8` image from dockerhub, but this can be
altered to use other images as well. There are currently a few lacking pieces
in the implementation, like re-using a manifest if present or trying to keep
all downloaded files/layers from skopeo.

This is *not* a substitue for the `anchore-manager analyze` command that produces
a tarball for analyzing.
"""
import json
import os
import pprint
import shutil
import subprocess
from os.path import abspath, dirname, join
from uuid import uuid4

import click

from anchore_engine.clients.localanchore_standalone import analyze_image

current = dirname(abspath(__file__))
top_level = dirname(dirname(dirname(dirname(current))))
cache_path = join(top_level, ".cache")


def call(command, stop_on_error=False):
    click.echo("Running command: %s" % " ".join(command))
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )

    returncode = process.wait()
    if returncode != 0:
        msg = "command returned non-zero exit status: %s" % returncode
        click.echo(msg)
        if stop_on_error:
            raise SystemExit(returncode)


def run(command):
    click.echo("Running command: %s" % " ".join(command))
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        close_fds=True,
    )

    stdout_stream = process.stdout.read()
    stderr_stream = process.stderr.read()

    returncode = process.wait()

    if not isinstance(stdout_stream, str):
        stdout_stream = stdout_stream.decode("utf-8")
    if not isinstance(stderr_stream, str):
        stderr_stream = stderr_stream.decode("utf-8")

    stdout = stdout_stream.splitlines()
    stderr = stderr_stream.splitlines()

    if returncode != 0:
        for line in stdout + stderr:
            click.echo(">>> %s" % line)
        click.echo("Command failed with non-zero exit status: %s" % returncode)

    return stdout, stderr, returncode


def get_manifest(resource, destination):
    """
    This optional helper should be preferred but `docker manifest` is an
    experimental feature and thus CircleCI does not support it with
    remote-docker.

    See https://docs.docker.com/engine/reference/commandline/manifest_inspect/

    If the `manifest inspect` call fails, it will load the previously loaded
    manifest from `scripts/manifests/` using the `resource` as the identifier
    for the JSON file.

    :resource: The full URI to use to get the manifest, with a sha digest
    :save_to: Absolute path to use to save the manifest
    """
    command = ["docker", "manifest", "inspect", resource]
    manifest, stderr, code = run(command)

    if code != 0:
        manifests_dir = join(current, "manifests")
        json_path = join(manifests_dir, "%s.json" % resource)
        with open(json_path, "r") as _f:
            json_manifest = _f.read()
            manifest = json.loads(json_manifest)
    else:
        json_manifest = "".join(manifest)
        manifest = json.loads(json_manifest)
    with open(destination, "w") as save_path:
        json.dump(manifest, save_path)
    click.echo("Saved manifest to: %s" % destination)
    # This returns the actual JSON, not the dict version, because the analyzer
    # really wants to deal with JSON directly
    return json_manifest


def analyze(registry, manifest, repo, digest, tag, work_dir, localconfig):
    userId = None  # Not used at all in analyze_image
    image_record = {
        "dockerfile_mode": "actual",  # XXX no idea
        "image_detail": [
            {  # always picks the first one
                "registry": registry,
                "repo": repo,
                "imageDigest": digest,
                "tag": tag,
                "imageId": "XXX",  # XXX no idea
                "dockerfile": None,
            }
        ],
        "imageDigest": "some sha256 - this seems repeated?",  # XXX
    }
    _localconfig = {"service_dir": join(work_dir, "service_dir")}
    if localconfig:
        _localconfig.update(localconfig)

    localconfig = _localconfig

    click.echo("Starting the analyze process...")

    image_report, manifest = analyze_image(
        userId,
        manifest,
        image_record,
        work_dir,
        localconfig,
        use_cache_dir=join(work_dir, "cache_dir"),
    )
    click.echo("Completed analyze process. Saving results...")
    result_python = join(work_dir, "result.py")
    with open(result_python, "w") as python_file:
        python_file.write("result = ")
        python_file.write(pprint.pformat(image_report))
    click.echo("Saved the results of the analyzer to %s" % result_python)


def create_directories(work_dir):
    """
    Create a set of directories needed to save the data, skip creation if they
    are there
    """
    os.makedirs(work_dir, exist_ok=True)
    if work_dir == cache_path:
        work_dir = join(cache_path, str(uuid4())[:8])

    os.makedirs(work_dir, exist_ok=True)

    service_dir = "service_dir"
    sub_directories = [service_dir, "cache_dir"]
    for _dir in sub_directories:
        os.makedirs(join(work_dir, _dir), exist_ok=True)
    # add analyzer config file
    current_path = os.path.dirname(os.path.realpath(__file__))
    config_source = join(current_path, "analyzer_config.yaml")
    config_dest = join(work_dir, service_dir, "analyzer_config.yaml")
    shutil.copyfile(config_source, config_dest)
    # if work_dir changed, return it so that it can be re-used
    return work_dir


@click.command()
@click.option(
    "--registry",
    default="docker.io",
    help="TLD of a registry, like docker.io",
    show_default=True,
)
@click.option(
    "--repo",
    default="centos",
    help='Repo name, like "centos" (official ones) or "anchore/enterprise" for accounts',
    show_default=True,
)
@click.option(
    "--digest",
    default="sha256:85313b812ad747dd19cf18078795b576cc4ae9cd2ca2ccccd7b5c12722b2effd",
    help="The image digest as shown in the registry",
    show_default=True,
)
@click.option(
    "--tag",
    default="centos8",
    help="The tag for the given container",
    show_default=True,
)
@click.option(
    "--work-dir",
    type=click.Path(exists=False),
    default=cache_path,
    help="Path to place images and other files",
    show_default=True,
)
def _main(registry, repo, digest, tag, work_dir):
    main(registry, repo, digest, tag, work_dir)


def main(
    registry=None,
    repo=None,
    digest=None,
    tag=None,
    work_dir=None,
    localconfig=None,
    **kw,
):
    # Re-assign work_dir in case it is using the cache, which gets computed
    # dynamically
    work_dir = create_directories(work_dir)
    resource = "%s@%s" % (repo, digest)
    manifest = get_manifest(resource, join(work_dir, "manifest.json"))
    analyze(registry, manifest, repo, digest, tag, work_dir, localconfig)


if __name__ == "__main__":
    _main()
