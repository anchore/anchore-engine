from .apk import compare_versions as apk_compare_versions
from .deb import compare_versions as deb_compare_versions
from .rpm import compare_versions as rpm_compare_versions


def compare_package_versions(distro_flavor, pkg_a, ver_a, pkg_b, ver_b):
    """
    Compare this package's version with a package name and version.
    Returns an int with the standard __cmp__ semantics: -1 iff a<b, 0 iff a=b, 1 iff a>b

    :param distro_flavor: (str) the package type/distro type for the comparison ("RHEL", "DEB", "ALPINE")
    :param pkg_a: (str) package A's name
    :param ver_a: (str) package A's version
    :param pkg_b: (str) package B's name
    :param ver_b: (str) package B's version
    :return: int comparison output -1, 0, or 1
    """

    # if ret == 0, versions are equal
    # if ret > 0, vers A is greater than version B
    # if ret < 0, vers A is less than version B

    fulla = "-".join([str(pkg_a), str(ver_a)])
    fullb = "-".join([str(pkg_b), str(ver_b)])
    if fulla == fullb:
        return 0

    if distro_flavor == "RHEL":
        if rpm_compare_versions(ver_a, ver_b) < 0:
            return -1
        else:
            return 1

    elif distro_flavor == "DEB":
        if deb_compare_versions(ver_a, "lt", ver_b):
            return -1
        else:
            return 1
    elif distro_flavor == "ALPINE":
        if apk_compare_versions(ver_a, "lt", ver_b):
            return -1
        else:
            return 1
    else:
        raise ValueError("unsupported distro, cannot compare package versions")
