import pytest

params = [
    (
        "centos8",
        "/etc/GREP_COLORS",
        '[{"conffile": true, "digest": "e94e50735e137e769b40e230f019d5be755571129e0f7669c4570bb45c5c162e", "digestalgo": "sha256", "group": "root", "mode": "100644", "package": "grep", "size": "94", "user": "root"}]',
    ),
    (
        "centos8",
        "/etc/NetworkManager/dispatcher.d/11-dhclient",
        '[{"conffile": false, "digest": "752fff425446e7e9007d663775cfc87a2d63e5ecb9a723350c7481c8c02e0f99", "digestalgo": "sha256", "group": "root", "mode": "100755", "package": "dhcp-client", "size": "1062", "user": "root"}]',
    ),
    (
        "centos8",
        "/etc/X11/xinit/xinitrc.d/50-systemd-user.sh",
        '[{"conffile": true, "digest": "8de4483a0c44a7719a66c4c86f6d6d3011feb4729b61b82015cd74cbce313cf3", "digestalgo": "sha256", "group": "root", "mode": "100755", "package": "systemd", "size": "203", "user": "root"}]',
    ),
    (
        "secrets",
        "/bin/busybox",
        '[{"conffile": false, "digest": null, "digestalgo": "sha1", "group": "0", "mode": "0755", "package": "busybox", "size": null, "user": "0"}]',
    ),
    (
        "secrets",
        "/etc/crontabs/root",
        '[{"conffile": false, "digest": null, "digestalgo": "sha1", "group": "0", "mode": "0600", "package": "alpine-baselayout", "size": null, "user": "0"}]',
    ),
    (
        "secrets",
        "/etc/profile",
        '[{"conffile": false, "digest": null, "digestalgo": "sha1", "group": null, "mode": null, "package": "alpine-baselayout", "size": null, "user": null}]',
    ),
    (
        "stretch-slim",
        "/bin/bash",
        '[{"conffile": false, "digest": "ac56f4b8fac5739ccdb45777d313becf", "digestalgo": "md5", "group": null, "mode": null, "package": "bash", "size": null, "user": null}]',
    ),
    (
        "stretch-slim",
        "/bin/cat",
        '[{"conffile": false, "digest": "bc40ef08137c600253d2d9d04c67e7f7", "digestalgo": "md5", "group": null, "mode": null, "package": "coreutils", "size": null, "user": null}]',
    ),
    (
        "stretch-slim",
        "/etc/apt/trusted.gpg.d/debian-archive-stretch-automatic.gpg",
        '[{"conffile": true, "digest": "c82e16869fb2d6234aff8b63fa00fb65", "digestalgo": "md5", "group": null, "mode": null, "package": "debian-archive-keyring", "size": null, "user": null}]',
    ),
]


@pytest.mark.parametrize("image, path, file_meta", params)
def test_file_package_verify(analyzed_data, image, path, file_meta):
    data = analyzed_data(image)
    base = data["image"]["imagedata"]["analysis_report"]["file_package_verify"][
        "distro.pkgfilemeta"
    ]["base"]
    assert base[path] == file_meta
