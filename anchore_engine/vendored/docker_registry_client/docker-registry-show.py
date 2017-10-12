"""
Copyright 2015 Red Hat, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


from __future__ import absolute_import

import argparse
from docker_registry_client import DockerRegistryClient
import json
import logging
import requests


class CLI(object):
    def __init__(self):
        self.parser = argparse.ArgumentParser()
        excl_group = self.parser.add_mutually_exclusive_group()
        excl_group.add_argument("-q", "--quiet", action="store_true")
        excl_group.add_argument("-v", "--verbose", action="store_true")

        self.parser.add_argument('--verify-ssl', dest='verify_ssl',
                                 action='store_true')
        self.parser.add_argument('--no-verify-ssl', dest='verify_ssl',
                                 action='store_false')
        self.parser.add_argument('--api-version', metavar='VER', type=int)

        self.parser.add_argument('registry', metavar='REGISTRY', nargs=1,
                                 help='registry URL (including scheme)')
        self.parser.add_argument('repository', metavar='REPOSITORY', nargs='?',
                                 help='repository (including namespace)')
        self.parser.add_argument('ref', metavar='REF', nargs='?',
                                 help='tag or digest')
        self.parser.add_argument('--username', dest='username')
        self.parser.add_argument('--password', dest='password')

        self.parser.set_defaults(verify_ssl=True, api_version=None)

    def run(self):
        args = self.parser.parse_args()

        basic_config_args = {}
        if args.verbose:
            basic_config_args['level'] = logging.DEBUG
        elif args.quiet:
            basic_config_args['level'] = logging.WARNING

        logging.basicConfig(**basic_config_args)

        kwargs = {}
        if args.api_version:
            kwargs['api_version'] = args.api_version

        if args.username:
            kwargs['username'] = args.username

        if args.password:
            kwargs['password'] = args.password

        client = DockerRegistryClient(args.registry[0],
                                      verify_ssl=args.verify_ssl,
                                      **kwargs)

        if args.repository:
            if args.ref:
                self.show_manifest(client, args.repository, args.ref)
            else:
                self.show_tags(client, args.repository)
        else:
            self.show_repositories(client)

    def show_repositories(self, client):
        try:
            repositories = client.repositories()
        except requests.HTTPError as e:
            if e.response.status_code == requests.codes.not_found:
                print("Catalog/Search not supported")
            else:
                raise
        else:
            print("Repositories:")
            for repository in repositories.keys():
                print("  - {0}".format(repository))

    def show_tags(self, client, repository):
        try:
            repo = client.repository(repository)
        except requests.HTTPError as e:
            if e.response.status_code == requests.codes.not_found:
                print("Repository {0} not found".format(repository))
            else:
                raise
        else:
            print("Tags in repository {0}:".format(repository))
            for tag in repo.tags():
                print("  - {0}".format(tag))

    def show_manifest(self, client, repository, ref):
        try:
            repo = client.repository(repository)
        except requests.HTTPError as e:
            if e.response.status_code == requests.codes.not_found:
                print("Repository {0} not found".format(repository))
            else:
                raise
        else:
            assert client.api_version in [1, 2]
            if client.api_version == 2:
                manifest, digest = repo.manifest(ref)
                print("Digest: {0}".format(digest))
                print("Manifest:")
                print(json.dumps(manifest, indent=2, sort_keys=True))
            else:
                image = repo.image(ref)
                image_json = image.get_json()
                print("Image ID: {0}".format(image.image_id))
                print("Image JSON:")
                print(json.dumps(image_json, indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        cli = CLI()
        cli.run()
    except KeyboardInterrupt:
        pass
