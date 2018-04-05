"""
By convention, we move eol'd gates into this module to keep them separated and avoid naming conflicts for classes.

"""

from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger, LifecycleStates


class SuidModeDiffTrigger(BaseTrigger):
    __trigger_name__ = 'suidmodediff'
    __description__ = 'triggers if file is suid, but mode is different between the image and its base'
    __lifecycle_state__ = LifecycleStates.eol


class SuidFileAddTrigger(BaseTrigger):
    __trigger_name__ = 'suidfileadd'
    __description__ = 'triggers if the evaluated image has a file that is SUID and the base image does not'
    __lifecycle_state__ = LifecycleStates.eol


class SuidFileDelTrigger(BaseTrigger):
    __trigger_name__ = 'suidfiledel'
    __description__ = 'triggers if the base image has a SUID file, but the evaluated image does not'
    __lifecycle_state__ = LifecycleStates.eol


class SuidDiffTrigger(BaseTrigger):
    __trigger_name__ = 'suiddiff'
    __description__ = 'triggers if any one of the other events for this gate have triggered'
    __lifecycle_state__ = LifecycleStates.eol


class SuidDiffGate(Gate):
    __lifecycle_state__ = LifecycleStates.eol
    __gate_name__ = 'suiddiff'
    __description__ = 'SetUID File Checks'
    __triggers__ = [
        SuidDiffTrigger,
        SuidFileAddTrigger,
        SuidFileDelTrigger,
        SuidModeDiffTrigger
    ]


class BaseOutOfDateTrigger(BaseTrigger):
    __trigger_name__ = 'baseoutofdate'
    __description__ = 'triggers if the image\'s base image has been updated since the image was built/analyzed'
    __params__ = {}
    __lifecycle_state__ = LifecycleStates.eol


class ImageCheckGate(Gate):
    __gate_name__ = 'imagecheck'
    __description__ = 'Checks on image ancestry'
    __triggers__ = [BaseOutOfDateTrigger]
    __lifecycle_state__ = LifecycleStates.eol


class PkgDiffTrigger(BaseTrigger):
    __trigger_name__ = 'pkgdiff'
    __description__ = 'triggers if any one of the other events has triggered'
    __lifecycle_state__ = LifecycleStates.eol


class PkgVersionDiffTrigger(BaseTrigger):
    __trigger_name__ = 'pkgversiondiff'
    __description__ = 'triggers if the evaluated image has a package installed with a different version of the same package from a previous base image'
    __lifecycle_state__ = LifecycleStates.eol


class PkgAddTrigger(BaseTrigger):
    __trigger_name__ = 'pkgadd'
    __description__ = 'triggers if image contains a package that is not in its base'
    __lifecycle_state__ = LifecycleStates.eol


class PkgDelTrigger(BaseTrigger):
    __trigger_name__ = 'pkgdel'
    __description__ = 'triggers if image has removed a package that is installed in its base'
    __lifecycle_state__ = LifecycleStates.eol


class PkgDiffGate(Gate):
    __lifecycle_state__ = LifecycleStates.eol
    __gate_name__ = 'pkgdiff'
    __description__ = 'Distro Package Difference Checks From Base Image'
    __triggers__ = [
        PkgVersionDiffTrigger,
        PkgAddTrigger,
        PkgDelTrigger,
        PkgDiffTrigger
    ]
