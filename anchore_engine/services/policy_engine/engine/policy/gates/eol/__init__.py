"""
By convention, we move eol'd gates into this module to keep them separated and avoid naming conflicts for classes.

"""
from anchore_engine.db import Image
from anchore_engine.services.policy_engine.engine.policy.gate import (
    BaseGate,
    BaseTrigger,
    LifecycleStates,
)


class SuidModeDiffTrigger(BaseTrigger[Image]):
    __trigger_name__ = "suidmodediff"
    __description__ = (
        "triggers if file is suid, but mode is different between the image and its base"
    )
    __lifecycle_state__ = LifecycleStates.eol


class SuidFileAddTrigger(BaseTrigger[Image]):
    __trigger_name__ = "suidfileadd"
    __description__ = "triggers if the evaluated image has a file that is SUID and the base image does not"
    __lifecycle_state__ = LifecycleStates.eol


class SuidFileDelTrigger(BaseTrigger[Image]):
    __trigger_name__ = "suidfiledel"
    __description__ = (
        "triggers if the base image has a SUID file, but the evaluated image does not"
    )
    __lifecycle_state__ = LifecycleStates.eol


class SuidDiffTrigger(BaseTrigger[Image]):
    __trigger_name__ = "suiddiff"
    __description__ = (
        "triggers if any one of the other events for this gate have triggered"
    )
    __lifecycle_state__ = LifecycleStates.eol


class SuidDiffGate(BaseGate[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __gate_name__ = "suiddiff"
    __description__ = "SetUID File Checks"
    __triggers__ = [
        SuidDiffTrigger,
        SuidFileAddTrigger,
        SuidFileDelTrigger,
        SuidModeDiffTrigger,
    ]


class BaseOutOfDateTrigger(BaseTrigger[Image]):
    __trigger_name__ = "baseoutofdate"
    __description__ = "triggers if the image's base image has been updated since the image was built/analyzed"
    __params__ = {}
    __lifecycle_state__ = LifecycleStates.eol


class ImageCheckGate(BaseGate[Image]):
    __gate_name__ = "imagecheck"
    __description__ = "Checks on image ancestry"
    __triggers__ = [BaseOutOfDateTrigger]
    __lifecycle_state__ = LifecycleStates.eol


class PkgDiffTrigger(BaseTrigger[Image]):
    __trigger_name__ = "pkgdiff"
    __description__ = "triggers if any one of the other events has triggered"
    __lifecycle_state__ = LifecycleStates.eol


class PkgVersionDiffTrigger(BaseTrigger[Image]):
    __trigger_name__ = "pkgversiondiff"
    __description__ = "triggers if the evaluated image has a package installed with a different version of the same package from a previous base image"
    __lifecycle_state__ = LifecycleStates.eol


class PkgAddTrigger(BaseTrigger[Image]):
    __trigger_name__ = "pkgadd"
    __description__ = "triggers if image contains a package that is not in its base"
    __lifecycle_state__ = LifecycleStates.eol


class PkgDelTrigger(BaseTrigger[Image]):
    __trigger_name__ = "pkgdel"
    __description__ = (
        "triggers if image has removed a package that is installed in its base"
    )
    __lifecycle_state__ = LifecycleStates.eol


class PkgDiffGate(BaseGate[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __gate_name__ = "pkgdiff"
    __description__ = "Distro Package Difference Checks From Base Image"
    __triggers__ = [PkgVersionDiffTrigger, PkgAddTrigger, PkgDelTrigger, PkgDiffTrigger]


class LowSeverityTrigger(BaseTrigger[Image]):
    __trigger_name__ = "vulnlow"
    __description__ = 'Checks for "low" severity vulnerabilities found in an image'
    __vuln_levels__ = ["Low"]
    __lifecycle_state__ = LifecycleStates.eol


class MediumSeverityTrigger(BaseTrigger[Image]):
    __trigger_name__ = "vulnmedium"
    __description__ = 'Checks for "medium" severity vulnerabilities found in an image'
    __vuln_levels__ = ["Medium"]
    __lifecycle_state__ = LifecycleStates.eol


class HighSeverityTrigger(BaseTrigger[Image]):
    __trigger_name__ = "vulnhigh"
    __description__ = 'Checks for "high" severity vulnerabilities found in an image'
    __vuln_levels__ = ["High"]
    __lifecycle_state__ = LifecycleStates.eol


class CriticalSeverityTrigger(BaseTrigger[Image]):
    __trigger_name__ = "vulncritical"
    __description__ = 'Checks for "critical" severity vulnerabilities found in an image'
    __vuln_levels__ = ["Critical"]
    __lifecycle_state__ = LifecycleStates.eol


class UnknownSeverityTrigger(BaseTrigger[Image]):
    __trigger_name__ = "vulnunknown"
    __description__ = 'Checks for "unkonwn" or "negligible" severity vulnerabilities found in an image'
    __vuln_levels__ = ["Unknown", "Negligible", None]
    __lifecycle_state__ = LifecycleStates.eol


class FeedOutOfDateTrigger(BaseTrigger[Image]):
    __trigger_name__ = "feedoutofdate"
    __description__ = "Fires if the CVE data is older than the window specified by the parameter MAXAGE (unit is number of days)"
    __lifecycle_state__ = LifecycleStates.eol


class UnsupportedDistroTrigger(BaseTrigger[Image]):
    __trigger_name__ = "unsupporteddistro"
    __description__ = "Fires if a vulnerability scan cannot be run against the image due to lack of vulnerability feed data for the images distro"
    __lifecycle_state__ = LifecycleStates.eol


class AnchoreSecGate(BaseGate[Image]):
    __gate_name__ = "anchoresec"
    __description__ = "Vulnerability checks against distro packages"
    __lifecycle_state__ = LifecycleStates.eol
    __superceded_by__ = "vulnerabilities"

    __triggers__ = [
        LowSeverityTrigger,
        MediumSeverityTrigger,
        HighSeverityTrigger,
        CriticalSeverityTrigger,
        UnknownSeverityTrigger,
        FeedOutOfDateTrigger,
        UnsupportedDistroTrigger,
    ]


class VerifyTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "verify"
    __description__ = "Check package integrity against package db in in the image. Triggers for changes or removal or content in all or the selected DIRS param if provided, and can filter type of check with the CHECK_ONLY param"


class PkgNotPresentTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "pkgnotpresent"
    __description__ = (
        "triggers if the package(s) specified in the params are not installed in the container image. The parameters specify different types of matches.",
    )


class PackageCheckGate(BaseGate[Image]):
    __gate_name__ = "pkgcheck"
    __description__ = "Distro package checks"
    __lifecycle_state__ = LifecycleStates.eol
    __superceded_by__ = "packages"
    __triggers__ = [PkgNotPresentTrigger, VerifyTrigger]


class EffectiveUserTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "effectiveuser"
    __description__ = "Triggers if the effective user for the container is either root when not allowed or is not in a whitelist"


class DirectiveCheckTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "directivecheck"
    __description__ = "Triggers if any directives in the list are found to match the described condition in the dockerfile"


class ExposeTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "expose"
    __description__ = "triggers if Dockerfile is EXPOSEing ports that are not in ALLOWEDPORTS, or are in DENIEDPORTS"


class NoFromTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "nofrom"
    __params__ = None
    __description__ = "triggers if there is no FROM line specified in the Dockerfile"


class FromScratch(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "fromscratch"
    __description__ = 'triggers the FROM line specified "scratch" as the parent'


class NoTag(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "notag"
    __description__ = "triggers if the FROM container specifies a repo but no explicit, non-latest tag"


class Sudo(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "sudo"
    __description__ = "triggers if the Dockerfile contains operations running with sudo"


class VolumePresent(BaseTrigger[Image]):
    __trigger_name__ = "volumepresent"
    __description__ = "triggers if the Dockerfile contains a VOLUME line"
    __lifecycle_state__ = LifecycleStates.eol


class NoHealthCheck(BaseTrigger[Image]):
    __trigger_name__ = "nohealthcheck"
    __description__ = (
        "triggers if the Dockerfile does not contain any HEALTHCHECK instructions"
    )
    __msg__ = "Dockerfile does not contain any HEALTHCHECK instructions"
    __lifecycle_state__ = LifecycleStates.eol


class NoDockerfile(BaseTrigger[Image]):
    __trigger_name__ = "nodockerfile"
    __description__ = (
        "triggers if anchore analysis was performed without supplying a real Dockerfile"
    )
    __msg__ = "Image was not analyzed with an actual Dockerfile"
    __lifecycle_state__ = LifecycleStates.eol


class DockerfileGate(BaseGate[Image]):
    __gate_name__ = "dockerfilecheck"
    __description__ = "Check Dockerfile Instructions"
    __lifecycle_state__ = LifecycleStates.eol
    __superceded_by__ = "dockerfile"
    __triggers__ = [
        DirectiveCheckTrigger,
        EffectiveUserTrigger,
        ExposeTrigger,
        NoFromTrigger,
        FromScratch,
        NoTag,
        Sudo,
        VolumePresent,
        NoHealthCheck,
        NoDockerfile,
    ]


class ContentMatchTrigger(BaseTrigger[Image]):
    __trigger_name__ = "contentmatch"
    __description__ = "Triggers if the content search analyzer has found any matches.  If the parameter is set, then will only trigger against found matches that are also in the FILECHECK_CONTENTMATCH parameter list.  If the parameter is absent or blank, then the trigger will fire if the analyzer found any matches."
    __lifecycle_state__ = LifecycleStates.eol


class FilenameMatchTrigger(BaseTrigger[Image]):
    __trigger_name__ = "filenamematch"
    __description__ = "Triggers if a file exists in the container that matches with any of the regular expressions given as FILECHECK_NAMEREGEXP parameters."
    __lifecycle_state__ = LifecycleStates.eol


class SuidCheckTrigger(BaseTrigger[Image]):
    __trigger_name__ = "suidsgidcheck"
    __description__ = "Fires for each file found to have suid or sgid set"
    __lifecycle_state__ = LifecycleStates.eol


class FileCheckGate(BaseGate[Image]):
    __gate_name__ = "filecheck"
    __description__ = "Image File Checks"
    __superceded_by__ = "files"
    __lifecycle_state__ = LifecycleStates.eol
    __triggers__ = [ContentMatchTrigger, FilenameMatchTrigger, SuidCheckTrigger]


class FileNotStoredTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "filenotstored"
    __description__ = (
        "triggers if the /etc/passwd file is not present/stored in the evaluated image"
    )
    __params__ = None
    __msg__ = "FILENOTSTORED Cannot locate /etc/passwd in image stored files archive: check analyzer settings"


class UsernameMatchTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "usernamematch"
    __description__ = "triggers if specified username is found in the /etc/passwd file"


class UserIdMatchTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "useridmatch"
    __description__ = "triggers if specified user id is found in the /etc/passwd file"


class GroupIdMatchTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "groupidmatch"
    __description__ = "triggers if specified group id is found in the /etc/passwd file"


class ShellMatchTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "shellmatch"
    __description__ = "triggers if specified login shell for any user is found in the /etc/passwd file"


class PEntryMatchTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "pentrymatch"
    __description__ = (
        "triggers if specified entire passwd entry is found in the /etc/passwd file"
    )


class FileparsePasswordGate(BaseGate[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __superceded_by__ = "passwd_file"
    __gate_name__ = "fileparse_passwd"
    __description__ = "Checks against the content of /etc/passwd in the image"
    __triggers__ = [
        FileNotStoredTrigger,
        UsernameMatchTrigger,
        UserIdMatchTrigger,
        GroupIdMatchTrigger,
        ShellMatchTrigger,
        PEntryMatchTrigger,
    ]


class GemNotLatestTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "gemnotlatest"
    __description__ = "triggers if an installed GEM is not the latest version according to GEM data feed"


class GemNotOfficialTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "gemnotofficial"
    __description__ = "triggers if an installed GEM is not in the official GEM database, according to GEM data feed"


class GemBadVersionTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "gembadversion"
    __description__ = "triggers if an installed GEM version is not listed in the official GEM feed as a valid version"


class GemPkgFullMatchTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "gempkgfullmatch"
    __description__ = "triggers if the evaluated image has an GEM package installed that matches one in the list given as a param (package_name|vers)"


class GemPkgNameMatchTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "gempkgnamematch"
    __description__ = "triggers if the evaluated image has an GEM package installed that matches one in the list given as a param (package_name)"


class GemNoFeedTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "gemnofeed"
    __description__ = "triggers if anchore does not have access to the GEM data feed"
    __msg__ = "GEMNOFEED GEM packages are present but the anchore GEM feed is not available - will be unable to perform checks that require feed data"


class GemCheckGate(BaseGate[Image]):
    __superceded_by__ = "gems"
    __lifecycle_state__ = LifecycleStates.eol
    __gate_name__ = "gemcheck"
    __description__ = "Ruby Gem Checks"
    __triggers__ = [
        GemNotLatestTrigger,
        GemNotOfficialTrigger,
        GemBadVersionTrigger,
        GemPkgFullMatchTrigger,
        GemPkgNameMatchTrigger,
        GemNoFeedTrigger,
    ]


class ImageMetadataAttributeCheckTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "attributecheck"
    __description__ = "Evaluates a named image attribute against the given condition and fires if matched"


class ImageMetadataGate(BaseGate[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __superceded_by__ = "metadata"
    __gate_name__ = "metadatacheck"
    __description__ = "Checks against image metadata gathered during analysis"

    __triggers__ = [
        ImageMetadataAttributeCheckTrigger,
    ]


class FullMatchTrigger(BaseTrigger[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "licfullmatch"
    __description__ = "triggers if the evaluated image has a package installed with software distributed under the specified (exact match) license(s)"


class SubstringMatchTrigger(BaseImageTrigger):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "licsubmatch"
    __description__ = "triggers if the evaluated image has a package installed with software distributed under the specified (substring match) license(s)"


class LicenseBlacklistGate(BaseGate[Image]):
    __superceded_by__ = "licenses"
    __lifecycle_state__ = LifecycleStates.eol
    __gate_name__ = "licblacklist"
    __description__ = "Package License Blacklists"
    __triggers__ = [FullMatchTrigger, SubstringMatchTrigger]


class NpmNotLatestTrigger(BaseImageTrigger):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "npmnotlatest"
    __description__ = "triggers if an installed NPM is not the latest version according to NPM data feed"


class NpmNotOfficialTrigger(BaseImageTrigger):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "npmnotofficial"
    __description__ = "triggers if an installed NPM is not in the official NPM database, according to NPM data feed"


class NpmBadVersionTrigger(BaseImageTrigger):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "npmbadversion"
    __description__ = "triggers if an installed NPM version is not listed in the official NPM feed as a valid version"


class NpmPkgFullMatchTrigger(BaseImageTrigger):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "npmpkgfullmatch"
    __description__ = "triggers if the evaluated image has an NPM package installed that matches one in the list given as a param (package_name|vers)"


class NpmPkgNameMatchTrigger(BaseImageTrigger):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "npmpkgnamematch"
    __description__ = "triggers if the evaluated image has an NPM package installed that matches one in the list given as a param (package_name)"


class NpmNoFeedTrigger(BaseImageTrigger):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "npmnofeed"
    __description__ = "triggers if anchore does not have access to the NPM data feed"
    __msg__ = "NPMNOFEED NPM packages are present but the anchore NPM feed is not available - will be unable to perform checks that require feed data"


class NpmCheckGate(BaseGate[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __superceded_by__ = "npms"
    __gate_name__ = "npmcheck"
    __description__ = "NPM Checks"
    __triggers__ = [
        NpmNotLatestTrigger,
        NpmNotOfficialTrigger,
        NpmBadVersionTrigger,
        NpmPkgFullMatchTrigger,
        NpmPkgNameMatchTrigger,
        NpmNoFeedTrigger,
    ]


class PkgFullMatchTrigger(BaseImageTrigger):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "pkgfullmatch"
    __description__ = "triggers if the evaluated image has a package installed that matches one in the list given as a param (package_name|vers)"


class NameMatchTrigger(BaseImageTrigger):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "pkgnamematch"
    __description__ = "triggers if the evaluated image has a package installed that matches one in the list given as a param (package_name)"


class PackageBlacklistGate(BaseGate[Image]):
    __lifecycle_state__ = LifecycleStates.eol
    __superceded_by__ = "packages"
    __gate_name__ = "pkgblacklist"
    __description__ = "Distro Package Blacklists"
    __triggers__ = [PkgFullMatchTrigger, NameMatchTrigger]


class SecretContentMatchTrigger(BaseImageTrigger):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "contentmatch"
    __description__ = "Triggers if the content search analyzer has found any matches.  If the parameter is set, then will only trigger against found matches that are also in the SECRETCHECK_CONTENTREGEXP parameter list.  If the parameter is absent or blank, then the trigger will fire if the analyzer found any matches."


class SecretFilenameMatchTrigger(BaseImageTrigger):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = "filenamematch"
    __description__ = "Triggers if a file exists in the container that matches with any of the regular expressions given as SECRETCHECK_NAMEREGEXP parameters."


class SecretCheckGate(BaseGate[Image]):
    __superceded_by__ = "secret_scans"
    __lifecycle_state__ = LifecycleStates.eol
    __gate_name__ = "secretcheck"
    __description__ = "Checks for Secrets Found in the Image"
    __triggers__ = [SecretContentMatchTrigger, SecretFilenameMatchTrigger]
