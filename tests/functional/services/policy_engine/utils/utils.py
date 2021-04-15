from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ImagesByVulnerabilityQueryOptions:
    severity: Optional[str] = None
    namespace: Optional[str] = None
    affected_package: Optional[str] = None
    vendor_only: bool = True


@dataclass
class ImagesByVulnerabilityQuery:
    vulnerability_id: str
    affected_images: List[str]
    query_metadata: Optional[ImagesByVulnerabilityQueryOptions] = field(
        default_factory=ImagesByVulnerabilityQueryOptions
    )


@dataclass
class VulnerabilityQueryMetadata:
    affected_package: Optional[str] = None
    affected_package_version: Optional[str] = None
    namespace: Optional[str] = None


@dataclass
class VulnerabilityQuery:
    id: list
    expected_output_file: str
    query_metadata: Optional[VulnerabilityQueryMetadata] = field(
        default_factory=VulnerabilityQueryMetadata
    )
