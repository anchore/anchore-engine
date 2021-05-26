from dataclasses import dataclass, field
from typing import List, Dict

from anchore_engine.util.models import VulnerabilityMatch
from anchore_engine.subsys import logger


class FeedGroupRank:
    """
    Feed groups ranked by an integer value. Rank defaults to pre-defined value if the group is not not explicitly ranked

    This is a very simplistic ranking strategy that handles three categories - nvdv2, github and all others.
    The strategy translates to any-group is ranked > github >  nvdv2
    """

    __ranks__ = {"nvdv2": 1, "github": 10}
    __default__ = 100

    def get(self, feed_group: str):
        group_prefix = feed_group.split(":", 1)[0]

        return self.__ranks__.get(group_prefix, self.__default__)


# eq=True and frozen=True required for making the instance hashable
@dataclass(eq=True, frozen=True)
class VulnerabilityIdentity:
    vuln_id: str
    pkg_name: str
    pkg_version: str
    pkg_type: str
    pkg_path: str

    @classmethod
    def from_match(cls, vuln_match: VulnerabilityMatch):
        """
        Returns a list of identities from nvd references if available or a single identity with the vulnerability ID otherwise
        """
        if vuln_match.vulnerability.cvss_scores_nvd:
            # generate identity tuples using the nvd refs
            results = [
                VulnerabilityIdentity(
                    vuln_id=nvd_score.id,
                    pkg_name=vuln_match.artifact.name,
                    pkg_version=vuln_match.artifact.version,
                    pkg_type=vuln_match.artifact.pkg_type,
                    pkg_path=vuln_match.artifact.pkg_path,
                )
                for nvd_score in vuln_match.vulnerability.cvss_scores_nvd
            ]
        else:
            # no nvd refs, generate the identity tuple using the vulnerability id
            results = [
                VulnerabilityIdentity(
                    vuln_id=vuln_match.vulnerability.vulnerability_id,
                    pkg_name=vuln_match.artifact.name,
                    pkg_version=vuln_match.artifact.version,
                    pkg_type=vuln_match.artifact.pkg_type,
                    pkg_path=vuln_match.artifact.pkg_path,
                )
            ]

        return results


@dataclass(eq=True, frozen=True)
class RankedVulnerabilityMatch:
    vuln_id: str
    vuln_namespace: str
    pkg_name: str
    pkg_version: str
    pkg_type: str
    pkg_path: str
    rank: int

    # leave the match out from hashing and equals comparison
    match_obj: VulnerabilityMatch = field(compare=False, repr=False)

    @classmethod
    def from_match(cls, match: VulnerabilityMatch, rank_strategy: FeedGroupRank):
        """
        Computes and returns the rank for the vulnerability match
        """
        return RankedVulnerabilityMatch(
            vuln_id=match.vulnerability.vulnerability_id,
            vuln_namespace=match.vulnerability.feed_group,
            pkg_name=match.artifact.name,
            pkg_version=match.artifact.version,
            pkg_type=match.artifact.pkg_type,
            pkg_path=match.artifact.pkg_path,
            rank=rank_strategy.get(match.vulnerability.feed_group),
            match_obj=match,
        )


class ImageVulnerabilitiesDeduplicator:
    """
    A mechanism for finding and removing duplicates from a list of vulnerability matches for an image

    Employs a configurable strategy to compute the rank of a given record and picks the record with the highest rank when there are duplicates
    """

    __rank_strategy__ = FeedGroupRank

    def __init__(self, strategy):
        if not strategy:
            self.rank_strategy = self.__rank_strategy__()
        else:
            self.rank_strategy = strategy

    def execute(
        self, vulnerability_matches: List[VulnerabilityMatch]
    ) -> List[VulnerabilityMatch]:
        """
        Finds duplicate records (for a specific definition of duplicate) in the provided list of vulnerability matches.
        Uses a defined strategy to rank such records and selects the highest ranking record to de-duplicate.

        Matches are considered duplicate when they affect the same package - identified by its name and location, and
        seemingly refer to the same vulnerability. The latter is explained by the following examples

        1. Match A contains vulnerability x with an nvd reference to vulnerability y in namespace z.
        Match B contains vulnerability y in the nvdv2 namespace. Matches A and B are duplicates.
        This is observed in feeds that don't use CVE IDs such as GHSA, ELSA, ALAS etc
        2. Match A contains vulnerability x in namespace y. Match B contains vulnerability x in namespace z.
        Matches A and B are duplicates.
        """

        if not vulnerability_matches:
            return []

        # de-dup is centered around nvd references. so pivot the data set first and create an identity
        # using nvd identifiers when available. map this nvd identity to the vulnerability
        # VulnerabilityIdentity -> RankedVulnerabilityMatch
        identity_map = dict()

        for vuln_match in vulnerability_matches:
            # get the rank tuple first
            ranked_match_object = RankedVulnerabilityMatch.from_match(
                vuln_match, self.rank_strategy
            )

            # get identity objects
            identity_objects = VulnerabilityIdentity.from_match(vuln_match)

            # now map each identity to the vulnerability. Rank and select as you go
            for identity_object in identity_objects:
                existing = identity_map.get(identity_object)
                if existing:
                    # identity is already mapped to a match, get the mapped vulnerability and compare ranks
                    if ranked_match_object.rank > existing.rank:
                        # current vulnerability rank is higher than existing, re-map
                        identity_map[identity_object] = ranked_match_object
                else:
                    # identity encountered first time, create a mapping to the vulnerability
                    identity_map[identity_object] = ranked_match_object

        # At this point identity_map contains unique nvd identities, each mapped to a vulnerability.
        # Mapped values may be repeated because of the initial data pivot.
        # So pivot back and gather unique vulnerabilities

        # set operation over a list of RankedVulnerabilityMatch removes duplicates by comparing everything but match object
        final_matches = [item.match_obj for item in set(identity_map.values())]

        logger.debug(
            "Deduplicated %d matches to %d",
            len(vulnerability_matches),
            len(final_matches),
        )

        return final_matches


def get_image_vulnerabilities_deduper():
    return ImageVulnerabilitiesDeduplicator(FeedGroupRank())


def transfer_vulnerability_timestamps(
    destination: List[VulnerabilityMatch], source: List[VulnerabilityMatch]
) -> List[VulnerabilityMatch]:
    """
    Transfers the match detected at and fix observed at timestamps from the source to destination report

    :param source:
    :param destination:
    """
    if not source or not destination:
        return []

    destination_map = _transform_vuln_match_list_to_map(destination)
    source_map = _transform_vuln_match_list_to_map(source)

    for identity_tuple in destination_map.keys():
        source_match = source_map.get(identity_tuple)
        if source_match:
            destination_match = destination_map.get(identity_tuple)
            destination_match.match.detected_at = source_match.match.detected_at
            # TODO something similar for fix observed at as well

    return list(destination_map.values())


def _transform_vuln_match_list_to_map(
    vuln_matches: List[VulnerabilityMatch],
) -> Dict[str, VulnerabilityMatch]:
    """
    Returns a dict from a list of VulnerabilityMatch objects where the key is a tuple representation of VulnerabilityMatch
    Choosing a tuple over other data structures for the key as it to be the quickest in terms of instantiation

    """
    if vuln_matches:
        return {match.identity_tuple(): match for match in vuln_matches}
    else:
        return {}
