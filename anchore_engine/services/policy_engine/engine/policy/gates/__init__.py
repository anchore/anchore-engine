# Import all valid gates

from .always import AlwaysGate

# Bring in deprecated gates
from .deprecated import *
from .dockerfile import DockerfileGate

# Bring in eol'd gates
from .eol import *
from .files import FileCheckGate
from .gems import GemCheckGate
from .image_metadata import ImageMetadataGate
from .licenses import LicensesGate
from .malware import MalwareGate
from .npms import NpmCheckGate
from .packages import PackagesCheckGate
from .passwd_file import FileparsePasswordGate
from .retrieved_files import RetrievedFileChecksGate
from .secrets import SecretCheckGate
from .vulnerabilities import VulnerabilitiesGate
