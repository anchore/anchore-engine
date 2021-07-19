"""
Tests for docker utils

"""
import pytest

from anchore_engine.util.docker import (
    DockerV2ManifestMetadata,
    DockerV1ManifestMetadata,
)

cloudfleet_nginx_v1_manifest = {
    "name": "cloudfleet/nginx",
    "tag": "latest",
    "architecture": "amd64",
    "fsLayers": [
        {
            "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
        },
        {
            "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
        },
        {
            "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
        },
        {
            "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
        },
        {
            "blobSum": "sha256:0bb4699e94e348add67a8637ed55623aa5a751f1cc33495a1cf8fe3b44197ea7"
        },
        {
            "blobSum": "sha256:c5c9f010f40eb247e861691ed83210851f1859683b3c24b71bbeed9e3bc0b7b2"
        },
        {
            "blobSum": "sha256:98d46fdc9351c08e07d74af042002224d09aa54dbd671e127f66c0fc6cf9ce1e"
        },
        {
            "blobSum": "sha256:590605bbf2b861d8be1f94611d3c585537a6b4b506c36895cf5a2fb62cfda660"
        },
        {
            "blobSum": "sha256:98a09f72e8b684307da695961846a2d848bf6413d1e81c86b4aa9500bf96809d"
        },
        {
            "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
        },
        {
            "blobSum": "sha256:7bdbf7d44e963c2af71f93b08b0fae167e9f1c63f3d409342765d1abd9b537b0"
        },
    ],
    "history": [
        {
            "v1Compatibility": '{"id":"1947ea680bc13ef558997dc88c0fb6b027fe2978e2cfc8c1db150cb4aeb1dc1b","parent":"7ca0d63b6d067bad8c77239d49dc0a7b4f0ff56638f2bc94ca3cbc5a8c876de6","created":"2015-05-12T18:16:42.393016552Z","container":"82a543d79460fcc4b15257fa69cca520487572a5fc9b81408ca9d32099163399","container_config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":{"443/tcp":{},"80/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","#(nop) CMD [\\"nginx\\" \\"-g\\" \\"daemon off;\\"]"],"Image":"7ca0d63b6d067bad8c77239d49dc0a7b4f0ff56638f2bc94ca3cbc5a8c876de6","Volumes":{"/var/cache/nginx":{}},"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"docker_version":"1.6.1-rc2","config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":{"443/tcp":{},"80/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["nginx","-g","daemon off;"],"Image":"7ca0d63b6d067bad8c77239d49dc0a7b4f0ff56638f2bc94ca3cbc5a8c876de6","Volumes":{"/var/cache/nginx":{}},"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"architecture":"amd64","os":"linux","Size":0}\n'
        },
        {
            "v1Compatibility": '{"id":"1947ea680bc13ef558997dc88c0fb6b027fe2978e2cfc8c1db150cb4aeb1dc1b","parent":"7ca0d63b6d067bad8c77239d49dc0a7b4f0ff56638f2bc94ca3cbc5a8c876de6","created":"2015-05-12T18:16:42.393016552Z","container":"82a543d79460fcc4b15257fa69cca520487572a5fc9b81408ca9d32099163399","container_config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":{"443/tcp":{},"80/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","#(nop) CMD [\\"nginx\\" \\"-g\\" \\"daemon off;\\"]"],"Image":"7ca0d63b6d067bad8c77239d49dc0a7b4f0ff56638f2bc94ca3cbc5a8c876de6","Volumes":{"/var/cache/nginx":{}},"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"docker_version":"1.6.1-rc2","config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":{"443/tcp":{},"80/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["nginx","-g","daemon off;"],"Image":"7ca0d63b6d067bad8c77239d49dc0a7b4f0ff56638f2bc94ca3cbc5a8c876de6","Volumes":{"/var/cache/nginx":{}},"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"architecture":"amd64","os":"linux","Size":0}\n'
        },
        {
            "v1Compatibility": '{"id":"7ca0d63b6d067bad8c77239d49dc0a7b4f0ff56638f2bc94ca3cbc5a8c876de6","parent":"90291c7e7f42b0e8343b2ac8a1fe4dcce4013fe521d920e8f8af4eb4e03d3a66","created":"2015-05-12T18:16:41.073739713Z","container":"7a12da8943cb15e4eee8ff25d36761e2cb862b8006fb417fd173aa356a160b90","container_config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":{"443/tcp":{},"80/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","#(nop) EXPOSE 443/tcp 80/tcp"],"Image":"90291c7e7f42b0e8343b2ac8a1fe4dcce4013fe521d920e8f8af4eb4e03d3a66","Volumes":{"/var/cache/nginx":{}},"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"docker_version":"1.6.1-rc2","config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":{"443/tcp":{},"80/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/bash"],"Image":"90291c7e7f42b0e8343b2ac8a1fe4dcce4013fe521d920e8f8af4eb4e03d3a66","Volumes":{"/var/cache/nginx":{}},"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"architecture":"amd64","os":"linux","Size":0}\n'
        },
        {
            "v1Compatibility": '{"id":"90291c7e7f42b0e8343b2ac8a1fe4dcce4013fe521d920e8f8af4eb4e03d3a66","parent":"a1c3678356396b50ec3a5e068bbe45a7f18138d0cf817e6b8d8d4ef1aa96008c","created":"2015-05-12T18:16:39.743289443Z","container":"883d7d33a81b92c8f6bf84e1ccf189e25f6322ac5cd92bfe0e4b26368cf979da","container_config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","#(nop) VOLUME [/var/cache/nginx]"],"Image":"a1c3678356396b50ec3a5e068bbe45a7f18138d0cf817e6b8d8d4ef1aa96008c","Volumes":{"/var/cache/nginx":{}},"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"docker_version":"1.6.1-rc2","config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/bash"],"Image":"a1c3678356396b50ec3a5e068bbe45a7f18138d0cf817e6b8d8d4ef1aa96008c","Volumes":{"/var/cache/nginx":{}},"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"architecture":"amd64","os":"linux","Size":0}\n'
        },
        {
            "v1Compatibility": '{"id":"a1c3678356396b50ec3a5e068bbe45a7f18138d0cf817e6b8d8d4ef1aa96008c","parent":"16d660787adcd5ce1a4121e974c877a209137b49012b9b33375cd2ce4cd04be0","created":"2015-05-12T18:16:38.480132726Z","container":"16821f75779e2b8007c7760296e1b966feb00b60b67631cd58f9e48d80e35efd","container_config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","ln -sf /dev/stderr /var/log/nginx/error.log"],"Image":"16d660787adcd5ce1a4121e974c877a209137b49012b9b33375cd2ce4cd04be0","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"docker_version":"1.6.1-rc2","config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/bash"],"Image":"16d660787adcd5ce1a4121e974c877a209137b49012b9b33375cd2ce4cd04be0","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"architecture":"amd64","os":"linux","Size":0}\n'
        },
        {
            "v1Compatibility": '{"id":"16d660787adcd5ce1a4121e974c877a209137b49012b9b33375cd2ce4cd04be0","parent":"3859458e16a43f8f6c2086d2510762ac4a7850dfb279483b80fc5c2027c642fe","created":"2015-05-12T18:16:37.01504938Z","container":"b2579863265ba170c6bbcc42b947c7a32a0b1026a5ccdadf1cba647711818a30","container_config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","ln -sf /dev/stdout /var/log/nginx/access.log"],"Image":"3859458e16a43f8f6c2086d2510762ac4a7850dfb279483b80fc5c2027c642fe","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"docker_version":"1.6.1-rc2","config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/bash"],"Image":"3859458e16a43f8f6c2086d2510762ac4a7850dfb279483b80fc5c2027c642fe","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"architecture":"amd64","os":"linux","Size":0}\n'
        },
        {
            "v1Compatibility": '{"id":"3859458e16a43f8f6c2086d2510762ac4a7850dfb279483b80fc5c2027c642fe","parent":"939efb5dbdd684006cb755a4c8d32b76675091fe965b3fb8cbbe815fd0b10399","created":"2015-05-12T18:16:35.578496699Z","container":"1546a4d6bd66c33de0c98c30b567b8b746128df1944253156610f9f4d6646bb9","container_config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","#(nop) ADD file:7c5fd1b31307655c5d6f8002a5e5a64ec0890bcb29a67d645fa2cbde03296746 in /etc/nginx/conf.d/default.conf"],"Image":"939efb5dbdd684006cb755a4c8d32b76675091fe965b3fb8cbbe815fd0b10399","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"docker_version":"1.6.1-rc2","config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/bash"],"Image":"939efb5dbdd684006cb755a4c8d32b76675091fe965b3fb8cbbe815fd0b10399","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"architecture":"amd64","os":"linux","Size":1096}\n'
        },
        {
            "v1Compatibility": '{"id":"939efb5dbdd684006cb755a4c8d32b76675091fe965b3fb8cbbe815fd0b10399","parent":"d5b32c12bc5b611c2cbd0c13e235a8a79355c37a9228e0ae856716b668b09e73","created":"2015-05-12T18:16:34.233246667Z","container":"f3226e852fb73b495a74dc10f5582283ce7c11aa9f249a3a032c98a60f3c1924","container_config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","rm /etc/nginx/sites-enabled/default"],"Image":"d5b32c12bc5b611c2cbd0c13e235a8a79355c37a9228e0ae856716b668b09e73","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"docker_version":"1.6.1-rc2","config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/bash"],"Image":"d5b32c12bc5b611c2cbd0c13e235a8a79355c37a9228e0ae856716b668b09e73","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"architecture":"amd64","os":"linux","Size":0}\n'
        },
        {
            "v1Compatibility": '{"id":"d5b32c12bc5b611c2cbd0c13e235a8a79355c37a9228e0ae856716b668b09e73","parent":"41b730702607edf9b07c6098f0b704ff59c5d4361245e468c0d551f50eae6f84","created":"2015-05-12T18:16:32.077521673Z","container":"12e7e3993f13a9df6d864ba9bd347a308f2f8de59ed00d8fdce6686931e7c9d9","container_config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh","-c","apt-get update \\u0026\\u0026 apt-get install -y nginx-extras"],"Image":"41b730702607edf9b07c6098f0b704ff59c5d4361245e468c0d551f50eae6f84","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"docker_version":"1.6.1-rc2","config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/bash"],"Image":"41b730702607edf9b07c6098f0b704ff59c5d4361245e468c0d551f50eae6f84","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":[],"Labels":{}},"architecture":"amd64","os":"linux","Size":71974941}\n'
        },
        {
            "v1Compatibility": '{"id":"41b730702607edf9b07c6098f0b704ff59c5d4361245e468c0d551f50eae6f84","parent":"3cb35ae859e76583ba7707df18ea7417e8d843682f4e5440a5279952c47fd8d8","created":"2015-04-29T17:30:06.654618646Z","container":"ee8ac26653bf498609067339d6b59bc3fa702a21c0d401758ffc0d53628733d1","container_config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":null,"Cmd":["/bin/sh","-c","#(nop) CMD [\\"/bin/bash\\"]"],"Image":"3cb35ae859e76583ba7707df18ea7417e8d843682f4e5440a5279952c47fd8d8","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":null,"Labels":{}},"docker_version":"1.6.0","config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":null,"Cmd":["/bin/bash"],"Image":"3cb35ae859e76583ba7707df18ea7417e8d843682f4e5440a5279952c47fd8d8","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":null,"Labels":{}},"architecture":"amd64","os":"linux","Size":0}\n'
        },
        {
            "v1Compatibility": '{"id":"3cb35ae859e76583ba7707df18ea7417e8d843682f4e5440a5279952c47fd8d8","created":"2015-04-29T17:30:05.171992057Z","container":"d85bc6285be49ed2106bc6dde14e33e379559892a95c3bb33f88377407c44c5b","container_config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":null,"Cmd":["/bin/sh","-c","#(nop) ADD file:96977352301efe982eb2ed967416521e4bf09e96c7f7d6fb06c63edebe91d785 in /"],"Image":"","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":null,"Labels":null},"docker_version":"1.6.0","config":{"Hostname":"d85bc6285be4","Domainname":"","User":"","Memory":0,"MemorySwap":0,"CpuShares":0,"Cpuset":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"PortSpecs":null,"ExposedPorts":null,"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":null,"Cmd":null,"Image":"","Volumes":null,"WorkingDir":"","Entrypoint":null,"NetworkDisabled":false,"MacAddress":"","OnBuild":null,"Labels":null},"architecture":"amd64","os":"linux","Size":125119001}\n'
        },
    ],
    "schemaVersion": 1,
    "signatures": [
        {
            "header": {
                "jwk": {
                    "crv": "P-256",
                    "kid": "FLMC:ZNUX:YO6P:5VYR:V3ZS:VB4L:3G3S:3L45:DEMX:TPJY:YKUP:TQLO",
                    "kty": "EC",
                    "x": "EFPNmgirbkKnmmeA1nXWsEh25PG8FlPpyNk4NG4vdY0",
                    "y": "_BsM67ND23-rZnp_Wb3IGV-byZPaiBN9XiRC1v9f0wA",
                },
                "alg": "ES256",
            },
            "signature": "ID32d-GIWR20nmGfE2MtZ7AUEw3H5-f8SZYotsn_YYDfXMPjQnNTSy1OUjoomN-whmEDDkZxjW1Tsgv3pbBxyA",
            "protected": "eyJmb3JtYXRMZW5ndGgiOjIwMzE3LCJmb3JtYXRUYWlsIjoiQ24wIiwidGltZSI6IjIwMTktMDEtMjNUMDE6MTM6NDdaIn0",
        }
    ],
}

cloudfleet_expected_layer_ids = [
    "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
    "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
    "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
    "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
    "sha256:0bb4699e94e348add67a8637ed55623aa5a751f1cc33495a1cf8fe3b44197ea7",
    "sha256:c5c9f010f40eb247e861691ed83210851f1859683b3c24b71bbeed9e3bc0b7b2",
    "sha256:98d46fdc9351c08e07d74af042002224d09aa54dbd671e127f66c0fc6cf9ce1e",
    "sha256:590605bbf2b861d8be1f94611d3c585537a6b4b506c36895cf5a2fb62cfda660",
    "sha256:98a09f72e8b684307da695961846a2d848bf6413d1e81c86b4aa9500bf96809d",
    "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
    "sha256:7bdbf7d44e963c2af71f93b08b0fae167e9f1c63f3d409342765d1abd9b537b0",
]
cloudfleet_expected_layer_ids.reverse()  # Copied here in order of manifest, but output from handler is in dockerfile order, so reverse this

cloudfleet_expected_history = [
    {
        "Id": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
        "Created": "2015-05-12T18:16:42.393016552Z",
        "CreatedBy": '/bin/sh -c #(nop) CMD ["nginx" "-g" "daemon off;"]',
        "Size": 0,
        "Comment": "",
        "Tags": [],
    },
    {
        "Id": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
        "Created": "2015-05-12T18:16:42.393016552Z",
        "CreatedBy": '/bin/sh -c #(nop) CMD ["nginx" "-g" "daemon off;"]',
        "Size": 0,
        "Comment": "",
        "Tags": [],
    },
    {
        "Id": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
        "Created": "2015-05-12T18:16:41.073739713Z",
        "CreatedBy": "/bin/sh -c #(nop) EXPOSE 443/tcp 80/tcp",
        "Size": 0,
        "Comment": "",
        "Tags": [],
    },
    {
        "Id": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
        "Created": "2015-05-12T18:16:39.743289443Z",
        "CreatedBy": "/bin/sh -c #(nop) VOLUME [/var/cache/nginx]",
        "Size": 0,
        "Comment": "",
        "Tags": [],
    },
    {
        "Id": "sha256:0bb4699e94e348add67a8637ed55623aa5a751f1cc33495a1cf8fe3b44197ea7",
        "Created": "2015-05-12T18:16:38.480132726Z",
        "CreatedBy": "/bin/sh -c ln -sf /dev/stderr /var/log/nginx/error.log",
        "Size": 0,
        "Comment": "",
        "Tags": [],
    },
    {
        "Id": "sha256:c5c9f010f40eb247e861691ed83210851f1859683b3c24b71bbeed9e3bc0b7b2",
        "Created": "2015-05-12T18:16:37.01504938Z",
        "CreatedBy": "/bin/sh -c ln -sf /dev/stdout /var/log/nginx/access.log",
        "Size": 0,
        "Comment": "",
        "Tags": [],
    },
    {
        "Id": "sha256:98d46fdc9351c08e07d74af042002224d09aa54dbd671e127f66c0fc6cf9ce1e",
        "Created": "2015-05-12T18:16:35.578496699Z",
        "CreatedBy": "/bin/sh -c #(nop) ADD file:7c5fd1b31307655c5d6f8002a5e5a64ec0890bcb29a67d645fa2cbde03296746 in /etc/nginx/conf.d/default.conf",
        "Size": 1096,
        "Comment": "",
        "Tags": [],
    },
    {
        "Id": "sha256:590605bbf2b861d8be1f94611d3c585537a6b4b506c36895cf5a2fb62cfda660",
        "Created": "2015-05-12T18:16:34.233246667Z",
        "CreatedBy": "/bin/sh -c rm /etc/nginx/sites-enabled/default",
        "Size": 0,
        "Comment": "",
        "Tags": [],
    },
    {
        "Id": "sha256:98a09f72e8b684307da695961846a2d848bf6413d1e81c86b4aa9500bf96809d",
        "Created": "2015-05-12T18:16:32.077521673Z",
        "CreatedBy": "/bin/sh -c apt-get update && apt-get install -y nginx-extras",
        "Size": 71974941,
        "Comment": "",
        "Tags": [],
    },
    {
        "Id": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
        "Created": "2015-04-29T17:30:06.654618646Z",
        "CreatedBy": '/bin/sh -c #(nop) CMD ["/bin/bash"]',
        "Size": 0,
        "Comment": "",
        "Tags": [],
    },
    {
        "Id": "sha256:7bdbf7d44e963c2af71f93b08b0fae167e9f1c63f3d409342765d1abd9b537b0",
        "Created": "2015-04-29T17:30:05.171992057Z",
        "CreatedBy": "/bin/sh -c #(nop) ADD file:96977352301efe982eb2ed967416521e4bf09e96c7f7d6fb06c63edebe91d785 in /",
        "Size": 125119001,
        "Comment": "",
        "Tags": [],
    },
]

nginx_manifest = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    "config": {
        "mediaType": "application/vnd.docker.container.image.v1+json",
        "size": 7474,
        "digest": "sha256:daee903b4e436178418e41d8dc223b73632144847e5fe81d061296e667f16ef2",
    },
    "layers": [
        {
            "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "size": 27105484,
            "digest": "sha256:852e50cd189dfeb54d97680d9fa6bed21a6d7d18cfb56d6abfe2de9d7f173795",
        },
        {
            "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "size": 26492338,
            "digest": "sha256:a29b129f410924b8ca6289b0e958f3d5ac159e29b54e4d9ab33e51eb87857474",
        },
        {
            "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "size": 600,
            "digest": "sha256:b3ddf1fa5595a82768da495f49d416bae8806d06ffe705935b4573035d8cfbad",
        },
        {
            "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "size": 895,
            "digest": "sha256:c5df295936d31cee0907f9652ff1b0518482ea87102f4cd2a872ed720e72314b",
        },
        {
            "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "size": 667,
            "digest": "sha256:232bf38931fc8c7f00f73e6d2be46776bd5b0999eb4c190c810a74cf203b1474",
        },
    ],
}

nginx_image_config = {
    "created": "2020-11-25T00:30:19.011398516Z",
    "architecture": "amd64",
    "os": "linux",
    "config": {
        "ExposedPorts": {"80/tcp": {}},
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "NGINX_VERSION=1.19.5",
            "NJS_VERSION=0.4.4",
            "PKG_RELEASE=1~buster",
        ],
        "Entrypoint": ["/docker-entrypoint.sh"],
        "Cmd": ["nginx", "-g", "daemon off;"],
        "Labels": {
            "maintainer": "NGINX Docker Maintainers \u003cdocker-maint@nginx.com\u003e"
        },
        "StopSignal": "SIGQUIT",
    },
    "rootfs": {
        "type": "layers",
        "diff_ids": [
            "sha256:f5600c6330da7bb112776ba067a32a9c20842d6ecc8ee3289f1a713b644092f8",
            "sha256:7ccabd267c9f125d6eeac54e32f6fbb338431828a3ee4c61600a301205e16627",
            "sha256:850c2400ea4dc52c17a0a8f8dd740628fbbf2fac8c24ce12f5c540f2d8e4a835",
            "sha256:f790aed835eec5d82dae9e0cbb9021063d9fe71885542f11b7a46631176301f7",
            "sha256:7e914612e36657b45436586984a556f9d3762e8e03374c6cd8c5d9e460a00c51",
        ],
    },
    "history": [
        {
            "created": "2020-11-17T20:21:17.570073346Z",
            "created_by": "/bin/sh -c #(nop) ADD file:d2abb0e4e7ac1773741f51f57d3a0b8ffc7907348842d773f8c341ba17f856d5 in / ",
        },
        {
            "created": "2020-11-17T20:21:17.865210281Z",
            "created_by": '/bin/sh -c #(nop)  CMD ["bash"]',
            "empty_layer": True,
        },
        {
            "created": "2020-11-18T07:48:00.110721952Z",
            "created_by": "/bin/sh -c #(nop)  LABEL maintainer=NGINX Docker Maintainers \u003cdocker-maint@nginx.com\u003e",
            "empty_layer": True,
        },
        {
            "created": "2020-11-25T00:29:56.371877659Z",
            "created_by": "/bin/sh -c #(nop)  ENV NGINX_VERSION=1.19.5",
            "empty_layer": True,
        },
        {
            "created": "2020-11-25T00:29:56.558437582Z",
            "created_by": "/bin/sh -c #(nop)  ENV NJS_VERSION=0.4.4",
            "empty_layer": True,
        },
        {
            "created": "2020-11-25T00:29:56.751806164Z",
            "created_by": "/bin/sh -c #(nop)  ENV PKG_RELEASE=1~buster",
            "empty_layer": True,
        },
        {
            "created": "2020-11-25T00:30:17.57116275Z",
            "created_by": '/bin/sh -c set -x     \u0026\u0026 addgroup --system --gid 101 nginx     \u0026\u0026 adduser --system --disabled-login --ingroup nginx --no-create-home --home /nonexistent --gecos "nginx user" --shell /bin/false --uid 101 nginx     \u0026\u0026 apt-get update     \u0026\u0026 apt-get install --no-install-recommends --no-install-suggests -y gnupg1 ca-certificates     \u0026\u0026     NGINX_GPGKEY=573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62;     found=\'\';     for server in         ha.pool.sks-keyservers.net         hkp://keyserver.ubuntu.com:80         hkp://p80.pool.sks-keyservers.net:80         pgp.mit.edu     ; do         echo "Fetching GPG key $NGINX_GPGKEY from $server";         apt-key adv --keyserver "$server" --keyserver-options timeout=10 --recv-keys "$NGINX_GPGKEY" \u0026\u0026 found=yes \u0026\u0026 break;     done;     test -z "$found" \u0026\u0026 echo \u003e\u00262 "error: failed to fetch GPG key $NGINX_GPGKEY" \u0026\u0026 exit 1;     apt-get remove --purge --auto-remove -y gnupg1 \u0026\u0026 rm -rf /var/lib/apt/lists/*     \u0026\u0026 dpkgArch="$(dpkg --print-architecture)"     \u0026\u0026 nginxPackages="         nginx=${NGINX_VERSION}-${PKG_RELEASE}         nginx-module-xslt=${NGINX_VERSION}-${PKG_RELEASE}         nginx-module-geoip=${NGINX_VERSION}-${PKG_RELEASE}         nginx-module-image-filter=${NGINX_VERSION}-${PKG_RELEASE}         nginx-module-njs=${NGINX_VERSION}+${NJS_VERSION}-${PKG_RELEASE}     "     \u0026\u0026 case "$dpkgArch" in         amd64|i386|arm64)             echo "deb https://nginx.org/packages/mainline/debian/ buster nginx" \u003e\u003e /etc/apt/sources.list.d/nginx.list             \u0026\u0026 apt-get update             ;;         *)             echo "deb-src https://nginx.org/packages/mainline/debian/ buster nginx" \u003e\u003e /etc/apt/sources.list.d/nginx.list                         \u0026\u0026 tempDir="$(mktemp -d)"             \u0026\u0026 chmod 777 "$tempDir"                         \u0026\u0026 savedAptMark="$(apt-mark showmanual)"                         \u0026\u0026 apt-get update             \u0026\u0026 apt-get build-dep -y $nginxPackages             \u0026\u0026 (                 cd "$tempDir"                 \u0026\u0026 DEB_BUILD_OPTIONS="nocheck parallel=$(nproc)"                     apt-get source --compile $nginxPackages             )                         \u0026\u0026 apt-mark showmanual | xargs apt-mark auto \u003e /dev/null             \u0026\u0026 { [ -z "$savedAptMark" ] || apt-mark manual $savedAptMark; }                         \u0026\u0026 ls -lAFh "$tempDir"             \u0026\u0026 ( cd "$tempDir" \u0026\u0026 dpkg-scanpackages . \u003e Packages )             \u0026\u0026 grep \'^Package: \' "$tempDir/Packages"             \u0026\u0026 echo "deb [ trusted=yes ] file://$tempDir ./" \u003e /etc/apt/sources.list.d/temp.list             \u0026\u0026 apt-get -o Acquire::GzipIndexes=false update             ;;     esac         \u0026\u0026 apt-get install --no-install-recommends --no-install-suggests -y                         $nginxPackages                         gettext-base                         curl     \u0026\u0026 apt-get remove --purge --auto-remove -y \u0026\u0026 rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx.list         \u0026\u0026 if [ -n "$tempDir" ]; then         apt-get purge -y --auto-remove         \u0026\u0026 rm -rf "$tempDir" /etc/apt/sources.list.d/temp.list;     fi     \u0026\u0026 ln -sf /dev/stdout /var/log/nginx/access.log     \u0026\u0026 ln -sf /dev/stderr /var/log/nginx/error.log     \u0026\u0026 mkdir /docker-entrypoint.d',
        },
        {
            "created": "2020-11-25T00:30:17.836060586Z",
            "created_by": "/bin/sh -c #(nop) COPY file:e7e183879c35719c18aa7f733651029fbcc55f5d8c22a877ae199b389425789e in / ",
        },
        {
            "created": "2020-11-25T00:30:18.056486094Z",
            "created_by": "/bin/sh -c #(nop) COPY file:08ae525f517706a57131e1efe03acba0fdd4ecadddb55301484f05d2ec76c39a in /docker-entrypoint.d ",
        },
        {
            "created": "2020-11-25T00:30:18.271434949Z",
            "created_by": "/bin/sh -c #(nop) COPY file:0fd5fca330dcd6a7de297435e32af634f29f7132ed0550d342cad9fd20158258 in /docker-entrypoint.d ",
        },
        {
            "created": "2020-11-25T00:30:18.459378195Z",
            "created_by": '/bin/sh -c #(nop)  ENTRYPOINT ["/docker-entrypoint.sh"]',
            "empty_layer": True,
        },
        {
            "created": "2020-11-25T00:30:18.635079822Z",
            "created_by": "/bin/sh -c #(nop)  EXPOSE 80",
            "empty_layer": True,
        },
        {
            "created": "2020-11-25T00:30:18.820138413Z",
            "created_by": "/bin/sh -c #(nop)  STOPSIGNAL SIGQUIT",
            "empty_layer": True,
        },
        {
            "created": "2020-11-25T00:30:19.011398516Z",
            "created_by": '/bin/sh -c #(nop)  CMD ["nginx" "-g" "daemon off;"]',
            "empty_layer": True,
        },
    ],
}

nginx_image_config_no_history = {
    "created": "2020-11-25T00:30:19.011398516Z",
    "architecture": "amd64",
    "os": "linux",
    "config": {
        "ExposedPorts": {"80/tcp": {}},
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "NGINX_VERSION=1.19.5",
            "NJS_VERSION=0.4.4",
            "PKG_RELEASE=1~buster",
        ],
        "Entrypoint": ["/docker-entrypoint.sh"],
        "Cmd": ["nginx", "-g", "daemon off;"],
        "Labels": {
            "maintainer": "NGINX Docker Maintainers \u003cdocker-maint@nginx.com\u003e"
        },
        "StopSignal": "SIGQUIT",
    },
    "rootfs": {
        "type": "layers",
        "diff_ids": [
            "sha256:f5600c6330da7bb112776ba067a32a9c20842d6ecc8ee3289f1a713b644092f8",
            "sha256:7ccabd267c9f125d6eeac54e32f6fbb338431828a3ee4c61600a301205e16627",
            "sha256:850c2400ea4dc52c17a0a8f8dd740628fbbf2fac8c24ce12f5c540f2d8e4a835",
            "sha256:f790aed835eec5d82dae9e0cbb9021063d9fe71885542f11b7a46631176301f7",
            "sha256:7e914612e36657b45436586984a556f9d3762e8e03374c6cd8c5d9e460a00c51",
        ],
    },
}

expected_history = [
    {
        "Created": "2020-11-17T20:21:17.570073346Z",
        "CreatedBy": "/bin/sh -c #(nop) ADD file:d2abb0e4e7ac1773741f51f57d3a0b8ffc7907348842d773f8c341ba17f856d5 in / ",
        "Size": 27105484,
        "Id": "sha256:852e50cd189dfeb54d97680d9fa6bed21a6d7d18cfb56d6abfe2de9d7f173795",
        "Tags": [],
        "Comment": "",
    },
    {
        "Created": "2020-11-17T20:21:17.865210281Z",
        "CreatedBy": '/bin/sh -c #(nop)  CMD ["bash"]',
        "Id": "<missing>",
        "Tags": [],
        "Comment": "",
        "Size": 0,
    },
    {
        "Created": "2020-11-18T07:48:00.110721952Z",
        "CreatedBy": "/bin/sh -c #(nop)  LABEL maintainer=NGINX Docker Maintainers \u003cdocker-maint@nginx.com\u003e",
        "Id": "<missing>",
        "Tags": [],
        "Comment": "",
        "Size": 0,
    },
    {
        "Created": "2020-11-25T00:29:56.371877659Z",
        "CreatedBy": "/bin/sh -c #(nop)  ENV NGINX_VERSION=1.19.5",
        "Id": "<missing>",
        "Tags": [],
        "Comment": "",
        "Size": 0,
    },
    {
        "Created": "2020-11-25T00:29:56.558437582Z",
        "CreatedBy": "/bin/sh -c #(nop)  ENV NJS_VERSION=0.4.4",
        "Id": "<missing>",
        "Tags": [],
        "Comment": "",
        "Size": 0,
    },
    {
        "Created": "2020-11-25T00:29:56.751806164Z",
        "CreatedBy": "/bin/sh -c #(nop)  ENV PKG_RELEASE=1~buster",
        "Id": "<missing>",
        "Tags": [],
        "Comment": "",
        "Size": 0,
    },
    {
        "Created": "2020-11-25T00:30:17.57116275Z",
        "CreatedBy": '/bin/sh -c set -x     \u0026\u0026 addgroup --system --gid 101 nginx     \u0026\u0026 adduser --system --disabled-login --ingroup nginx --no-create-home --home /nonexistent --gecos "nginx user" --shell /bin/false --uid 101 nginx     \u0026\u0026 apt-get update     \u0026\u0026 apt-get install --no-install-recommends --no-install-suggests -y gnupg1 ca-certificates     \u0026\u0026     NGINX_GPGKEY=573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62;     found=\'\';     for server in         ha.pool.sks-keyservers.net         hkp://keyserver.ubuntu.com:80         hkp://p80.pool.sks-keyservers.net:80         pgp.mit.edu     ; do         echo "Fetching GPG key $NGINX_GPGKEY from $server";         apt-key adv --keyserver "$server" --keyserver-options timeout=10 --recv-keys "$NGINX_GPGKEY" \u0026\u0026 found=yes \u0026\u0026 break;     done;     test -z "$found" \u0026\u0026 echo \u003e\u00262 "error: failed to fetch GPG key $NGINX_GPGKEY" \u0026\u0026 exit 1;     apt-get remove --purge --auto-remove -y gnupg1 \u0026\u0026 rm -rf /var/lib/apt/lists/*     \u0026\u0026 dpkgArch="$(dpkg --print-architecture)"     \u0026\u0026 nginxPackages="         nginx=${NGINX_VERSION}-${PKG_RELEASE}         nginx-module-xslt=${NGINX_VERSION}-${PKG_RELEASE}         nginx-module-geoip=${NGINX_VERSION}-${PKG_RELEASE}         nginx-module-image-filter=${NGINX_VERSION}-${PKG_RELEASE}         nginx-module-njs=${NGINX_VERSION}+${NJS_VERSION}-${PKG_RELEASE}     "     \u0026\u0026 case "$dpkgArch" in         amd64|i386|arm64)             echo "deb https://nginx.org/packages/mainline/debian/ buster nginx" \u003e\u003e /etc/apt/sources.list.d/nginx.list             \u0026\u0026 apt-get update             ;;         *)             echo "deb-src https://nginx.org/packages/mainline/debian/ buster nginx" \u003e\u003e /etc/apt/sources.list.d/nginx.list                         \u0026\u0026 tempDir="$(mktemp -d)"             \u0026\u0026 chmod 777 "$tempDir"                         \u0026\u0026 savedAptMark="$(apt-mark showmanual)"                         \u0026\u0026 apt-get update             \u0026\u0026 apt-get build-dep -y $nginxPackages             \u0026\u0026 (                 cd "$tempDir"                 \u0026\u0026 DEB_BUILD_OPTIONS="nocheck parallel=$(nproc)"                     apt-get source --compile $nginxPackages             )                         \u0026\u0026 apt-mark showmanual | xargs apt-mark auto \u003e /dev/null             \u0026\u0026 { [ -z "$savedAptMark" ] || apt-mark manual $savedAptMark; }                         \u0026\u0026 ls -lAFh "$tempDir"             \u0026\u0026 ( cd "$tempDir" \u0026\u0026 dpkg-scanpackages . \u003e Packages )             \u0026\u0026 grep \'^Package: \' "$tempDir/Packages"             \u0026\u0026 echo "deb [ trusted=yes ] file://$tempDir ./" \u003e /etc/apt/sources.list.d/temp.list             \u0026\u0026 apt-get -o Acquire::GzipIndexes=false update             ;;     esac         \u0026\u0026 apt-get install --no-install-recommends --no-install-suggests -y                         $nginxPackages                         gettext-base                         curl     \u0026\u0026 apt-get remove --purge --auto-remove -y \u0026\u0026 rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx.list         \u0026\u0026 if [ -n "$tempDir" ]; then         apt-get purge -y --auto-remove         \u0026\u0026 rm -rf "$tempDir" /etc/apt/sources.list.d/temp.list;     fi     \u0026\u0026 ln -sf /dev/stdout /var/log/nginx/access.log     \u0026\u0026 ln -sf /dev/stderr /var/log/nginx/error.log     \u0026\u0026 mkdir /docker-entrypoint.d',
        "Size": 26492338,
        "Id": "sha256:a29b129f410924b8ca6289b0e958f3d5ac159e29b54e4d9ab33e51eb87857474",
        "Tags": [],
        "Comment": "",
    },
    {
        "Created": "2020-11-25T00:30:17.836060586Z",
        "CreatedBy": "/bin/sh -c #(nop) COPY file:e7e183879c35719c18aa7f733651029fbcc55f5d8c22a877ae199b389425789e in / ",
        "Size": 600,
        "Id": "sha256:b3ddf1fa5595a82768da495f49d416bae8806d06ffe705935b4573035d8cfbad",
        "Tags": [],
        "Comment": "",
    },
    {
        "Created": "2020-11-25T00:30:18.056486094Z",
        "CreatedBy": "/bin/sh -c #(nop) COPY file:08ae525f517706a57131e1efe03acba0fdd4ecadddb55301484f05d2ec76c39a in /docker-entrypoint.d ",
        "Size": 895,
        "Id": "sha256:c5df295936d31cee0907f9652ff1b0518482ea87102f4cd2a872ed720e72314b",
        "Tags": [],
        "Comment": "",
    },
    {
        "Created": "2020-11-25T00:30:18.271434949Z",
        "CreatedBy": "/bin/sh -c #(nop) COPY file:0fd5fca330dcd6a7de297435e32af634f29f7132ed0550d342cad9fd20158258 in /docker-entrypoint.d ",
        "Size": 667,
        "Id": "sha256:232bf38931fc8c7f00f73e6d2be46776bd5b0999eb4c190c810a74cf203b1474",
        "Tags": [],
        "Comment": "",
    },
    {
        "Created": "2020-11-25T00:30:18.459378195Z",
        "CreatedBy": '/bin/sh -c #(nop)  ENTRYPOINT ["/docker-entrypoint.sh"]',
        "Id": "<missing>",
        "Tags": [],
        "Comment": "",
        "Size": 0,
    },
    {
        "Created": "2020-11-25T00:30:18.635079822Z",
        "CreatedBy": "/bin/sh -c #(nop)  EXPOSE 80",
        "Id": "<missing>",
        "Tags": [],
        "Comment": "",
        "Size": 0,
    },
    {
        "Created": "2020-11-25T00:30:18.820138413Z",
        "CreatedBy": "/bin/sh -c #(nop)  STOPSIGNAL SIGQUIT",
        "Id": "<missing>",
        "Tags": [],
        "Comment": "",
        "Size": 0,
    },
    {
        "Created": "2020-11-25T00:30:19.011398516Z",
        "CreatedBy": '/bin/sh -c #(nop)  CMD ["nginx" "-g" "daemon off;"]',
        "Id": "<missing>",
        "Tags": [],
        "Comment": "",
        "Size": 0,
    },
]

expected_history_when_no_history = [
    {
        "Created": "",
        "CreatedBy": "",
        "Size": 27105484,
        "Id": "sha256:852e50cd189dfeb54d97680d9fa6bed21a6d7d18cfb56d6abfe2de9d7f173795",
        "Tags": [],
        "Comment": "",
    },
    {
        "Created": "",
        "CreatedBy": "",
        "Size": 26492338,
        "Id": "sha256:a29b129f410924b8ca6289b0e958f3d5ac159e29b54e4d9ab33e51eb87857474",
        "Tags": [],
        "Comment": "",
    },
    {
        "Created": "",
        "CreatedBy": "",
        "Size": 600,
        "Id": "sha256:b3ddf1fa5595a82768da495f49d416bae8806d06ffe705935b4573035d8cfbad",
        "Tags": [],
        "Comment": "",
    },
    {
        "Created": "",
        "CreatedBy": "",
        "Size": 895,
        "Id": "sha256:c5df295936d31cee0907f9652ff1b0518482ea87102f4cd2a872ed720e72314b",
        "Tags": [],
        "Comment": "",
    },
    {
        "Created": "",
        "CreatedBy": "",
        "Size": 667,
        "Id": "sha256:232bf38931fc8c7f00f73e6d2be46776bd5b0999eb4c190c810a74cf203b1474",
        "Tags": [],
        "Comment": "",
    },
]

expected_layer_ids = [
    "sha256:852e50cd189dfeb54d97680d9fa6bed21a6d7d18cfb56d6abfe2de9d7f173795",
    "sha256:a29b129f410924b8ca6289b0e958f3d5ac159e29b54e4d9ab33e51eb87857474",
    "sha256:b3ddf1fa5595a82768da495f49d416bae8806d06ffe705935b4573035d8cfbad",
    "sha256:c5df295936d31cee0907f9652ff1b0518482ea87102f4cd2a872ed720e72314b",
    "sha256:232bf38931fc8c7f00f73e6d2be46776bd5b0999eb4c190c810a74cf203b1474",
]


@pytest.mark.parametrize(
    "manifest, image_config, expected_history, expected_layer_ids",
    [
        (
            nginx_manifest,
            nginx_image_config,
            expected_history,
            expected_layer_ids,
        ),
        (
            nginx_manifest,
            nginx_image_config_no_history,
            expected_history_when_no_history,
            expected_layer_ids,
        ),
    ],
)
def test_dockerv2manifestmetadata(
    manifest, image_config, expected_history, expected_layer_ids
):
    t = DockerV2ManifestMetadata(manifest, image_config)
    assert t.history == expected_history
    assert t.layer_ids == expected_layer_ids


@pytest.mark.parametrize(
    "manifest, expected_history, expected_layer_ids",
    [
        (
            cloudfleet_nginx_v1_manifest,
            cloudfleet_expected_history,
            cloudfleet_expected_layer_ids,
        )
    ],
)
def test_dockerv1manifestmetadata(manifest, expected_history, expected_layer_ids):
    t = DockerV1ManifestMetadata(manifest)
    assert t.history == expected_history
    assert t.layer_ids == expected_layer_ids
