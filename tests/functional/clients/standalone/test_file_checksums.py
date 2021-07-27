import pytest

# from result[0]['image']['imagedata']['analysis_report']['file_checksums']['files.md5sums']['base']
# generated with:
# base_subset = [random.choice(list(base_md5_files.items())) for i in range(20)]
# base_subset = [(k, v) for k, v in base_subset if v != 'DIRECTORY_OR_OTHER']

base_md5_files = [
    ("/usr/share/terminfo/c/cons25", "5eb691998583e67c1d1d66f6d1b065ba"),
    (
        "/usr/lib/systemd/system/systemd-quotacheck.service",
        "63671090978f9a8bed49369cbde180f3",
    ),
    ("/etc/passwd-", "482d23f981a9580b8abecbfbf217b461"),
    ("/usr/lib/rpm/platform/pentium4-linux/macros", "6b32638136f96c56d92aa275d538553f"),
    (
        "/usr/lib/python3.6/site-packages/pip/_vendor/requests/hooks.py",
        "b073f8769b1bf45e9caed6fac944becf",
    ),
    (
        "/usr/lib64/python3.6/__pycache__/pdb.cpython-36.opt-2.pyc",
        "17b6549eff65ab451cc675a665100d71",
    ),
    ("/usr/lib64/gconv/IBM1156.so", "adaef8e3253ac6b4a3927fe2d65965c3"),
    (
        "/usr/lib64/python3.6/distutils/__pycache__/cygwinccompiler.cpython-36.opt-1.pyc",
        "733c3209d0c6bbb8173c1fb997c82639",
    ),
    (
        "/usr/lib64/python3.6/__pycache__/macpath.cpython-36.opt-1.pyc",
        "d6fe9a169908eaa083007178e0fff33e",
    ),
    (
        "/usr/lib64/python3.6/encodings/__pycache__/iso8859_6.cpython-36.opt-1.pyc",
        "4ee69916b8082bb9ef0492e7919264d6",
    ),
    ("/usr/share/zoneinfo/America/Moncton", "42cc0908b3130c6e299407ac07f48f3a"),
    ("/usr/lib64/python3.6/hashlib.py", "712be7b38fe0aa1278bd94b6e958c6b1"),
    (
        "/usr/lib64/python3.6/site-packages/hawkey/test/__pycache__/__init__.cpython-36.opt-1.pyc",
        "ca671cd78d8a808b51b5fd2f195a9614",
    ),
    (
        "/usr/lib/python3.6/site-packages/dnf/db/__init__.py",
        "61f7ffa26df791381a33800b3ad6bf8c",
    ),
    (
        "/usr/lib64/python3.6/lib2to3/pgen2/__pycache__/tokenize.cpython-36.pyc",
        "f957469172d51e862dd869e6f8ae512f",
    ),
]


base_sha256_files = [
    (
        "/usr/share/terminfo/x/xterm-1005",
        "db3f585af9406e3f119d2708ebe8381c465b17e827d668825901e65335613543",
    ),
    (
        "/usr/lib/systemd/system/systemd-binfmt.service",
        "9d76a773f37baec117c84de3dce32a3d308216786480f9ffa9030a388806099e",
    ),
    (
        "/usr/lib64/python3.6/encodings/__pycache__/johab.cpython-36.opt-2.pyc",
        "ee9838c5e877a344ce46a9e70e4b9ca4387db8eb627344e0df051649843aa98f",
    ),
    (
        "/usr/lib/python3.6/site-packages/setuptools/extern/__pycache__/__init__.cpython-36.opt-1.pyc",
        "f1ba04477b1f6bd1a1ff170d779c07ef91ead7cf0878fffbc7f4a0acca442ae7",
    ),
    (
        "/usr/share/zoneinfo/right/Australia/North",
        "a7223b77c9ca3ab6de014f4f9b566c79dd3f4161c5ea4223b6ff8608285535d9",
    ),
    (
        "/usr/lib64/python3.6/encodings/__pycache__/euc_kr.cpython-36.opt-1.pyc",
        "beb31a76a3c2192304fa9282b9c9f5f0de79e26c5134499b2fc555eee961bf1a",
    ),
    (
        "/usr/share/zoneinfo/right/Africa/Tripoli",
        "72bb85f8ac4ec74b2ae92214c047c82f1f39c9c0785d0f54e152b8c1d940adda",
    ),
    (
        "/usr/share/zoneinfo/America/Iqaluit",
        "eb8797250b8bd8c3d09893b4f261ffb1bedd668869a051c8e2c80f6c0d63408c",
    ),
    (
        "/usr/lib/python3.6/site-packages/pip/_vendor/chardet/escsm.py",
        "46e5e580dbd32036ab9ddbe594d0a4e56641229742c50d2471df4402ec5487ce",
    ),
    ("/usr/bin/cd", "efe0fc3df889d7046ebba2d60b7f0f1290be4d4874ffd6cd31372b183fc093b4"),
    (
        "/usr/share/zoneinfo/right/America/Lower_Princes",
        "ec9709d87bbdd0aae7be4070156e5dc05c12d822da203cb1030354342bae2df0",
    ),
    (
        "/usr/share/zoneinfo/Asia/Kathmandu",
        "5c557b86c5f0fdd19d105afbd38bd9daaad1cd075e9efdbe80547ddca85ae5ae",
    ),
    (
        "/usr/sbin/arpd",
        "997bd39f90c5d54b4b82768730a60b5f13822b9586cc0f6fdf932acb8cf32f8f",
    ),
    (
        "/usr/lib64/python3.6/asyncio/__pycache__/events.cpython-36.pyc",
        "363f35128c711bd37cbbd8fafb1ab2b4e777369ca9f1ae3158ff049cc72eac04",
    ),
    (
        "/usr/share/zoneinfo/posix/America/Eirunepe",
        "07761278f5c58867c645625c9b819ea09e4703d76564e231979e48d6d2e0881a",
    ),
    (
        "/usr/share/zoneinfo/right/GMT-0",
        "da4f5e177e0e5138774896d0b82b59cce878cf3700734a5d6cdfac2f0f96eb28",
    ),
    (
        "/usr/lib/python3.6/site-packages/pip/_vendor/urllib3/util/__pycache__/retry.cpython-36.opt-1.pyc",
        "f1bc93fa2135d70ed44db437c0a0cc43780269429989d4325a636e3c62a90b4e",
    ),
    (
        "/usr/lib/dracut/modules.d/98dracut-systemd/dracut-pre-trigger.sh",
        "ac40a755302a0d52c23b9460599a043b077719bfba16f580e57a4ad75d0dc31f",
    ),
    (
        "/usr/lib/systemd/system/slices.target",
        "db8b99e38e60072fb7495482e4e18afb8804fa0c9bb8572355bc68311c653ece",
    ),
    (
        "/usr/bin/gio-querymodules-64",
        "322e1677953eb5bbce3bdbe65bed19713c28b86e3ba1ccaed53fd3c8ba74b181",
    ),
]

base_md5_directories = [
    "/usr/lib64/security/pam_filter",
    "/usr/lib/systemd/system/sysinit.target.wants/ldconfig.service",
    "/usr/sbin/modinfo",
    "/usr/lib/.build-id/89/da144167418cccb5d2117823b8c573a5984268",
    "/usr/lib/.build-id/4a/caf76a47856c8835c8b1d54ab47aa5b26c669b",
    "/usr/lib/.build-id/13",
    "/usr/lib64/libpcap.so.1",
    "/usr/share/licenses/gpgme",
    "/usr/sbin/resolvconf",
    "/usr/lib/.build-id/a7/ea49730ede02ab8510d158f346463048773fe8",
    "/usr/lib/.build-id/36/faedeff8cee9807b9166adb2116e42312663d6",
    "/usr/lib/.build-id/b0/4bc78ad983e0841b7ed0495e05360db1b9fa60",
    "/usr/lib64/python3.6/multiprocessing/__pycache__",
    "/usr/lib/systemd/portable",
    "/usr/lib64/bind9-export",
    "/usr/share/licenses/hostname",
    "/usr/lib/.build-id/83/1c579dc8576b1e3b3518f4b98fc7f746256be4",
    "/usr/share/terminfo/h",
    "/usr/share/licenses/libassuan",
    "/usr/lib64/libpcap.so.1",
]

base_sha256_directories = [
    "/usr/share/doc/xz",
    "/usr/lib/python3.6/site-packages/setuptools/_vendor/__pycache__",
    "/usr/lib/.build-id/42/69c307d08a5e4996505d1d2e6be30f113701f3",
    "/usr/lib/.build-id/c0/cb8ca8993a57dd509bedc6c61987739500e12f",
    "/etc/dhcp/dhclient.d",
    "/usr/lib/systemd/system/sysinit.target.wants/dracut-shutdown.service",
    "/usr/lib/.build-id/8b/41259a9dcac23b9d25b1eadec05f7f5f119e85",
    "/usr/lib/.build-id/20/5d96b4ead1e34e91cbb7c7b32e15125d9c3486",
    "/usr/sbin/depmod",
    "/usr/lib/rpm/platform/pentium4-linux",
    "/usr/lib/rpm/platform/mipsr6el-linux",
    "/usr/lib/.build-id/a1/50051e8416c265135f94d988de4cd5c1af91a2",
    "/usr/lib64/libsasl2.so.3",
    "/usr/lib/python3.6/site-packages/pip/_vendor/urllib3/util/__pycache__",
    "/usr/local/share/man/man6",
    "/usr/lib/.build-id/11/01608b497da384792bb5d96e753fe3c333ca77",
    "/usr/lib/.build-id/af/c9d3df0248fba68df185628d3190d4458554d2",
    "/usr/lib64/python3.6/site-packages/__pycache__",
    "/usr/lib/.build-id/88",
    "/usr/lib/.build-id/f5/c9ed5027df3ef17b56963d2e7e619b6ef43d47",
]


@pytest.mark.parametrize("path", base_md5_directories)
def test_md5_directories(analyzed_data, path):
    data = analyzed_data()
    base = data["image"]["imagedata"]["analysis_report"]["file_checksums"][
        "files.md5sums"
    ]["base"]
    assert base[path] == "DIRECTORY_OR_OTHER"


@pytest.mark.parametrize("path, chsum", base_md5_files)
def test_md5_file_checksums(analyzed_data, path, chsum):
    data = analyzed_data()
    base = data["image"]["imagedata"]["analysis_report"]["file_checksums"][
        "files.md5sums"
    ]["base"]
    assert base[path] == chsum


@pytest.mark.parametrize("path", base_sha256_directories)
def test_sha256_directories(analyzed_data, path):
    data = analyzed_data()
    base = data["image"]["imagedata"]["analysis_report"]["file_checksums"][
        "files.sha256sums"
    ]["base"]
    assert base[path] == "DIRECTORY_OR_OTHER"


@pytest.mark.parametrize("path, chsum", base_sha256_files)
def test_sha256_file_checksums(analyzed_data, path, chsum):
    data = analyzed_data()
    base = data["image"]["imagedata"]["analysis_report"]["file_checksums"][
        "files.sha256sums"
    ]["base"]
    assert base[path] == chsum
