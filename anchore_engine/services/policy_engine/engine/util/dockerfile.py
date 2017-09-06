import re
from collections import namedtuple, OrderedDict

# TODO: complete dockerfile parser for easy checks and validation against any part of it
#
# def parse_dockerfile(dockerfile_content, is_guessed=False):
#     """
#     Given a single string as a dockerfile, parse it into a keyed dict.
#
#     :param dockerfile_content:
#     :param is_guessed:
#     :return:
#     """
#
#     structured_dockerfile = OrderedDict()
#
#     for line in dockerfile_content.split_lines():
#         line.strip()
#         if line.startswith('#'):
#             continue
#
#         entries = line.split()
#         command = entries[0].upper()
#         line = entries[1:]
#
#         structured_dockerfile[command].append(line)
#
#         if command == 'FROM':
#             # implied: 'FROM centos'
#             # full: 'FROM myhost.com:8000/user/repository:tag
#             # implied + host: 'FROM myhost.com:8000/user/repository
#             # digest: 'FROM centos@sha256:abaaba'
#             # 'FROM myhost.com:8000/user/repository@sha256:blahblahblah
#
#             from_target = line[0] # Only 1 entry on a from line other than command
#             if '@' in from_target:
#                 host_repo, digest = from_target.rsplit('@', 1)
#             elif ':' in from_target:
#                 host_repo, tag = from_target.rsplit(':', 1) # Ensure handling a port spec in hostname works
#             else:
#
#         elif command == 'RUN':
#             pass
#         elif command == 'CMD':
#             pass
#         elif command == 'ENV':
#             pass
#         elif command == 'MAINTAINER':
#             pass
#         elif command == 'EXPOSE':
#             pass
#         elif command == 'VOLUME':
#             pass
#         elif command == 'ENTRYPOINT':
#             pass
#         elif command == 'LABEL':
#             pass
#         elif command == 'ADD':
#             pass
#         elif command == 'COPY':
#             pass
#         elif command == 'USER':
#             pass
#         elif command == 'ARG':
#             pass
#         elif command == 'ONBUILD':
#             pass
#         elif command == 'STOPSIGNAL':
#             pass
#         elif command == 'HEALTHCHECK':
#             pass
#         elif command == 'SHELL':
#             pass


