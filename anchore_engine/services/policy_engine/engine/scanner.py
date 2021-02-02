"""
Module for returning vulnerability reports for images
"""
from anchore_engine.utils import timer


class DefaultVulnScanner:
    """
    Scanner object for scanning an image
    """

    def __init__(self, nvd_cls: type, cpe_cls: type):
        self.nvd_cls = nvd_cls
        self.cpe_cls = cpe_cls

    def get_vulnerabilities(self, image):
        return image.vulnerabilities()

    def get_cpe_vulnerabilities(self, image):
        with timer("Image vulnerability cpe lookups", log_level="debug"):
            return image.cpe_vulnerabilities(
                _nvd_cls=self.nvd_cls, _cpe_cls=self.cpe_cls
            )


scanner_type = DefaultVulnScanner


def get_scanner(nvd_cls, cpe_cls):
    """
    Return
    :param nvd_cls:
    :param cpe_cls:
    :return:
    """
    # Instantiate type defined in global config
    return scanner_type(nvd_cls, cpe_cls)
