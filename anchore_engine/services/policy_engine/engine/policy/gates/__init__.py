# Import all valid gates

from .dockerfile import DockerfileGate
from .file_content import FileCheckGate
from .fileparse_passwd import FileparsePasswordGate
from .image_base_check import ImageCheckGate
from .check_package_info import PackageCheckGate
from .check_pkgs import PkgDiffGate
from .anchoresec import AnchoreSecGate
from .package_blacklist import PackageBlacklistGate
from .check_suidfiles import SuidDiffGate
from .license_blacklist import LicenseBlacklistGate
from .gem_check import GemCheckGate
from .npm_check import NpmCheckGate
from .secret_check import SecretCheckGate
from .image_metadata import ImageMetadataGate
