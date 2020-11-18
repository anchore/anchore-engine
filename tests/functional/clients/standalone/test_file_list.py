import pytest

# from result[0]['image']['imagedata']['analysis_report']['file_list']['files.all']['base']
# generated with:
# files_all_subset = [random.choice(list(files_all.items())) for i in range(20)]

files_all_subset = [
    (
        "/usr/lib/python3.6/site-packages/pip/_vendor/urllib3/__pycache__/connection.cpython-36.pyc",
        "0o644",
    ),
    (
        "/usr/lib64/python3.6/lib2to3/fixes/__pycache__/fix_intern.cpython-36.opt-1.pyc",
        "0o644",
    ),
    ("/usr/lib/dracut/modules.d/80lvmmerge/README.md", "0o644"),
    ("/usr/lib64/libip6tc.so.0.1.0", "0o755"),
    (
        "/usr/lib/python3.6/site-packages/setuptools/_vendor/__pycache__/six.cpython-36.opt-1.pyc",
        "0o644",
    ),
    ("/usr/lib/.build-id/8e/9191dffa9f716362829472319d7834fadadc5a", "0o777"),
    (
        "/usr/lib/python3.6/site-packages/pip/_vendor/urllib3/contrib/_securetransport/__pycache__",
        "0o755",
    ),
    ("/usr/share/licenses/libseccomp/LICENSE", "0o644"),
    ("/usr/lib64/python3.6/__pycache__/copy.cpython-36.opt-1.pyc", "0o644"),
    ("/usr/lib64/python3.6/encodings/__pycache__/cp865.cpython-36.pyc", "0o644"),
    ("/usr/share/zoneinfo/iso3166.tab", "0o644"),
    ("/etc/host.conf", "0o644"),
    ("/usr/share/zoneinfo/right/America/Catamarca", "0o644"),
    ("/etc/libaudit.conf", "0o640"),
    ("/usr/lib/systemd/catalog/systemd.pt_BR.catalog", "0o644"),
    ("/usr/lib/systemd/system/dracut-shutdown.service", "0o777"),
    ("/usr/lib/.build-id/66/29051069454db7e5e097271a21c6bcc26d7f8d", "0o777"),
    ("/usr/share/licenses/libverto", "0o755"),
    ("/etc/ld.so.conf.d/bind-export-aarch64.conf", "0o644"),
    ("/usr/lib/systemd/system/dracut-initqueue.service", "0o777"),
]


allinfo_subset = [
    (
        "/usr/share/zoneinfo/posix/Australia/Currie",
        '{"name": "/usr/share/zoneinfo/posix/Australia/Currie", "fullpath": '
        '"/usr/share/zoneinfo/posix/Australia/Currie", "size": 2223, "mode": 33188, '
        '"uid": 0, "gid": 0, "linkdst": null, "linkdst_fullpath": null, "type": '
        '"file", "othernames": {"/usr/share/zoneinfo/posix/Australia/Currie": '
        "true}}",
    ),
    (
        "/usr/share/systemd/kbd-model-map",
        '{"name": "/usr/share/systemd/kbd-model-map", "fullpath": '
        '"/usr/share/systemd/kbd-model-map", "size": 3564, "mode": 33188, "uid": 0, '
        '"gid": 0, "linkdst": null, "linkdst_fullpath": null, "type": "file", '
        '"othernames": {"/usr/share/systemd/kbd-model-map": true}}',
    ),
    (
        "/usr/share/zoneinfo/right/Etc/GMT",
        '{"name": "/usr/share/zoneinfo/right/Etc/GMT", "fullpath": '
        '"/usr/share/zoneinfo/right/Etc/GMT", "size": 667, "mode": 33188, "uid": 0, '
        '"gid": 0, "linkdst": null, "linkdst_fullpath": null, "type": "file", '
        '"othernames": {"/usr/share/zoneinfo/right/Etc/GMT": true}}',
    ),
    (
        "/usr/share/zoneinfo/posix/Etc",
        '{"name": "/usr/share/zoneinfo/posix/Etc", "fullpath": '
        '"/usr/share/zoneinfo/posix/Etc", "size": 0, "mode": 16877, "uid": 0, "gid": '
        '0, "linkdst": null, "linkdst_fullpath": null, "type": "dir", "othernames": '
        '{"/usr/share/zoneinfo/posix/Etc": true}}',
    ),
    (
        "/usr/bin/gpgv",
        '{"name": "/usr/bin/gpgv", "fullpath": "/usr/bin/gpgv", "size": 498056, '
        '"mode": 33261, "uid": 0, "gid": 0, "linkdst": null, "linkdst_fullpath": '
        'null, "type": "file", "othernames": {"/usr/bin/gpgv": true}}',
    ),
    (
        "/usr/lib64/python3.6/encodings/__pycache__/cp737.cpython-36.pyc",
        '{"name": "/usr/lib64/python3.6/encodings/__pycache__/cp737.cpython-36.pyc", '
        '"fullpath": '
        '"/usr/lib64/python3.6/encodings/__pycache__/cp737.cpython-36.pyc", "size": '
        '8145, "mode": 33188, "uid": 0, "gid": 0, "linkdst": null, '
        '"linkdst_fullpath": null, "type": "file", "othernames": '
        '{"/usr/lib64/python3.6/encodings/__pycache__/cp737.cpython-36.pyc": true}}',
    ),
    (
        "/usr/lib/python3.6/site-packages/pip/_vendor/html5lib/treebuilders/__pycache__/etree_lxml.cpython-36.pyc",
        '{"name": '
        '"/usr/lib/python3.6/site-packages/pip/_vendor/html5lib/treebuilders/__pycache__/etree_lxml.cpython-36.pyc", '
        '"fullpath": '
        '"/usr/lib/python3.6/site-packages/pip/_vendor/html5lib/treebuilders/__pycache__/etree_lxml.cpython-36.pyc", '
        '"size": 11727, "mode": 33188, "uid": 0, "gid": 0, "linkdst": null, '
        '"linkdst_fullpath": null, "type": "file", "othernames": '
        '{"/usr/lib/python3.6/site-packages/pip/_vendor/html5lib/treebuilders/__pycache__/etree_lxml.cpython-36.pyc": '
        "true}}",
    ),
    (
        "/usr/lib/python3.6/site-packages/dnf/conf/__pycache__/substitutions.cpython-36.pyc",
        '{"name": '
        '"/usr/lib/python3.6/site-packages/dnf/conf/__pycache__/substitutions.cpython-36.pyc", '
        '"fullpath": '
        '"/usr/lib/python3.6/site-packages/dnf/conf/__pycache__/substitutions.cpython-36.pyc", '
        '"size": 1568, "mode": 33188, "uid": 0, "gid": 0, "linkdst": null, '
        '"linkdst_fullpath": null, "type": "file", "othernames": '
        '{"/usr/lib/python3.6/site-packages/dnf/conf/__pycache__/substitutions.cpython-36.pyc": '
        "true}}",
    ),
    (
        "/usr/share/zoneinfo/America/Argentina/San_Juan",
        '{"name": "/usr/share/zoneinfo/America/Argentina/San_Juan", "fullpath": '
        '"/usr/share/zoneinfo/America/Argentina/San_Juan", "size": 1123, "mode": '
        '33188, "uid": 0, "gid": 0, "linkdst": null, "linkdst_fullpath": null, '
        '"type": "file", "othernames": '
        '{"/usr/share/zoneinfo/America/Argentina/San_Juan": true}}',
    ),
    (
        "/usr/share/tabset/vt100",
        '{"name": "/usr/share/tabset/vt100", "fullpath": "/usr/share/tabset/vt100", '
        '"size": 160, "mode": 33188, "uid": 0, "gid": 0, "linkdst": null, '
        '"linkdst_fullpath": null, "type": "file", "othernames": '
        '{"/usr/share/tabset/vt100": true}}',
    ),
    (
        "/usr/share/zoneinfo/posix/America/Dominica",
        '{"name": "/usr/share/zoneinfo/posix/America/Dominica", "fullpath": '
        '"/usr/share/zoneinfo/posix/America/Dominica", "size": 170, "mode": 33188, '
        '"uid": 0, "gid": 0, "linkdst": null, "linkdst_fullpath": null, "type": '
        '"file", "othernames": {"/usr/share/zoneinfo/posix/America/Dominica": '
        "true}}",
    ),
    (
        "/usr/lib/python3.6/site-packages/pip/_vendor/urllib3/contrib/__pycache__/__init__.cpython-36.pyc",
        '{"name": '
        '"/usr/lib/python3.6/site-packages/pip/_vendor/urllib3/contrib/__pycache__/__init__.cpython-36.pyc", '
        '"fullpath": '
        '"/usr/lib/python3.6/site-packages/pip/_vendor/urllib3/contrib/__pycache__/__init__.cpython-36.pyc", '
        '"size": 113, "mode": 33188, "uid": 0, "gid": 0, "linkdst": null, '
        '"linkdst_fullpath": null, "type": "file", "othernames": '
        '{"/usr/lib/python3.6/site-packages/pip/_vendor/urllib3/contrib/__pycache__/__init__.cpython-36.pyc": '
        "true}}",
    ),
    (
        "/usr/lib/python3.6/site-packages/pip/_vendor/chardet/__pycache__/enums.cpython-36.pyc",
        '{"name": '
        '"/usr/lib/python3.6/site-packages/pip/_vendor/chardet/__pycache__/enums.cpython-36.pyc", '
        '"fullpath": '
        '"/usr/lib/python3.6/site-packages/pip/_vendor/chardet/__pycache__/enums.cpython-36.pyc", '
        '"size": 2539, "mode": 33188, "uid": 0, "gid": 0, "linkdst": null, '
        '"linkdst_fullpath": null, "type": "file", "othernames": '
        '{"/usr/lib/python3.6/site-packages/pip/_vendor/chardet/__pycache__/enums.cpython-36.pyc": '
        "true}}",
    ),
    (
        "/usr/lib/systemd/system/systemd-user-sessions.service",
        '{"name": "/usr/lib/systemd/system/systemd-user-sessions.service", '
        '"fullpath": "/usr/lib/systemd/system/systemd-user-sessions.service", '
        '"size": 636, "mode": 33188, "uid": 0, "gid": 0, "linkdst": null, '
        '"linkdst_fullpath": null, "type": "file", "othernames": '
        '{"/usr/lib/systemd/system/systemd-user-sessions.service": true}}',
    ),
    (
        "/usr/share/pki/ca-trust-source/anchors",
        '{"name": "/usr/share/pki/ca-trust-source/anchors", "fullpath": '
        '"/usr/share/pki/ca-trust-source/anchors", "size": 0, "mode": 16877, "uid": '
        '0, "gid": 0, "linkdst": null, "linkdst_fullpath": null, "type": "dir", '
        '"othernames": {"/usr/share/pki/ca-trust-source/anchors": true}}',
    ),
    (
        "/usr/lib64/python3.6/collections/__pycache__",
        '{"name": "/usr/lib64/python3.6/collections/__pycache__", "fullpath": '
        '"/usr/lib64/python3.6/collections/__pycache__", "size": 0, "mode": 16877, '
        '"uid": 0, "gid": 0, "linkdst": null, "linkdst_fullpath": null, "type": '
        '"dir", "othernames": {"/usr/lib64/python3.6/collections/__pycache__": '
        "true}}",
    ),
    (
        "/usr/lib/.build-id/00/769246dbd044617cffd76a6aec384c53af30d9",
        '{"name": "/usr/lib/.build-id/00/769246dbd044617cffd76a6aec384c53af30d9", '
        '"fullpath": "/usr/lib/.build-id/00/769246dbd044617cffd76a6aec384c53af30d9", '
        '"size": 40, "mode": 41471, "uid": 0, "gid": 0, "linkdst": '
        '"../../../../usr/lib64/gconv/NATS-DANO.so", "linkdst_fullpath": '
        '"/usr/lib/.build-id/00/769246dbd044617cffd76a6aec384c53af30d9", "type": '
        '"slink", "othernames": '
        '{"/usr/lib/.build-id/00/769246dbd044617cffd76a6aec384c53af30d9": true, '
        '"../../../../usr/lib64/gconv/NATS-DANO.so": true}}',
    ),
    (
        "/usr/share/licenses/zlib",
        '{"name": "/usr/share/licenses/zlib", "fullpath": '
        '"/usr/share/licenses/zlib", "size": 0, "mode": 16877, "uid": 0, "gid": 0, '
        '"linkdst": null, "linkdst_fullpath": null, "type": "dir", "othernames": '
        '{"/usr/share/licenses/zlib": true}}',
    ),
    (
        "/usr/lib/.build-id/3b/142e9178a43068ee4c86e0000d3751e25688d2",
        '{"name": "/usr/lib/.build-id/3b/142e9178a43068ee4c86e0000d3751e25688d2", '
        '"fullpath": "/usr/lib/.build-id/3b/142e9178a43068ee4c86e0000d3751e25688d2", '
        '"size": 25, "mode": 41471, "uid": 0, "gid": 0, "linkdst": '
        '"../../../../usr/bin/ipcrm", "linkdst_fullpath": '
        '"/usr/lib/.build-id/3b/142e9178a43068ee4c86e0000d3751e25688d2", "type": '
        '"slink", "othernames": '
        '{"/usr/lib/.build-id/3b/142e9178a43068ee4c86e0000d3751e25688d2": true, '
        '"../../../../usr/bin/ipcrm": true}}',
    ),
    (
        "/usr/lib64/python3.6/email/mime/__pycache__",
        '{"name": "/usr/lib64/python3.6/email/mime/__pycache__", "fullpath": '
        '"/usr/lib64/python3.6/email/mime/__pycache__", "size": 0, "mode": 16877, '
        '"uid": 0, "gid": 0, "linkdst": null, "linkdst_fullpath": null, "type": '
        '"dir", "othernames": {"/usr/lib64/python3.6/email/mime/__pycache__": '
        "true}}",
    ),
]


@pytest.mark.parametrize("path,metadata", allinfo_subset)
def test_allinfo(path, metadata, analyzed_data):
    report = analyzed_data()
    data = report["image"]["imagedata"]["analysis_report"]["file_list"][
        "files.allinfo"
    ]["base"]
    assert data[path] == metadata


@pytest.mark.parametrize("_file,bit", files_all_subset)
def test_files_all(_file, bit, analyzed_data):
    report = analyzed_data()
    data = report["image"]["imagedata"]["analysis_report"]["file_list"]["files.all"][
        "base"
    ]
    assert data[_file] == bit
