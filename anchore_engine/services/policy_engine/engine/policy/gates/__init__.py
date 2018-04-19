# Import all valid gates

from .dockerfile import DockerfileGate
from .files import FileCheckGate
from .passwd_file import FileparsePasswordGate
from .packages import PackagesCheckGate
from .vulnerabilities import VulnerabilitiesGate
from .licenses import LicensesGate
from .gems import GemCheckGate
from .npms import NpmCheckGate
from .secrets import SecretCheckGate
from .image_metadata import ImageMetadataGate
from .always import AlwaysGate

# Bring in deprecated gates
from .deprecated import *

# Bring in eol'd gates
from .eol import *
