import json
import time

from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.db import ImageCpe, CpeVulnerability

log = get_logger()

class CpeSeverityTrigger(BaseTrigger):
    __vuln_levels__ = []

    def evaluate(self, image_obj, context):
        severity_matches = context.data['severity_matches']
        for vuln_level in self.__vuln_levels__:
            if vuln_level not in severity_matches:
                continue

            for image_cpe, vulnerability_cpe in severity_matches[vuln_level]:
                message="matched a CPE vulnerability {} level {}".format(vulnerability_cpe.vulnerability_id, vuln_level)
                self._fire(instance_id="{}+{}".format(vulnerability_cpe.vulnerability_id, image_cpe.name+"-"+image_cpe.version), msg=message)
        

class LowSeverityTrigger(CpeSeverityTrigger):
    __trigger_name__ = 'vulnlow'
    __description__ = 'triggers if a vulnerability of LOW severity is found, along with a named package'
    __vuln_levels__ = ['Low']


class MediumSeverityTrigger(CpeSeverityTrigger):
    __trigger_name__ = 'vulnmedium'
    __description__ = 'triggers if a vulnerability of MEDIUM severity is found, along with a named package'
    __vuln_levels__ = ['Medium']


class HighSeverityTrigger(CpeSeverityTrigger):
    __trigger_name__ = 'vulnhigh'
    __description__ = 'triggers if a vulnerability of HIGH severity is found, along with a named package'
    __vuln_levels__ = ['High']


class UnknownSeverityTrigger(CpeSeverityTrigger):
    __trigger_name__ = 'vulnunknown'
    __description__ = 'triggers if a vulnerability of UNKNOWN severity is found, along with a named package'
    __vuln_levels__ = ['Unknown', 'Negligible', None]


class CpeGate(Gate):
    __gate_name__ = 'cpegate'
    __description__ = 'Fires triggers when NVD CPE vulnerability matches are found'
    __triggers__ = [
        LowSeverityTrigger,
        MediumSeverityTrigger,
        HighSeverityTrigger,
        UnknownSeverityTrigger
    ]

    def prepare_context(self, image_obj, context):
        timer = time.time()
        #all_cpe_matches = context.db.query(ImageCpe,CpeVulnerability,NvdMetadata).filter(ImageCpe.image_id==image_obj.id).filter(ImageCpe.name==CpeVulnerability.name).filter(ImageCpe.version==CpeVulnerability.version).filter(NvdMetadata.name==CpeVulnerability.vulnerability_id)
        all_cpe_matches = context.db.query(ImageCpe,CpeVulnerability).filter(ImageCpe.image_id==image_obj.id).filter(ImageCpe.name==CpeVulnerability.name).filter(ImageCpe.version==CpeVulnerability.version)
        if not all_cpe_matches:
            all_cpe_matches = []

        severity_matches = {}
        #for image_cpe, vulnerability_cpe, nvd_metadata in all_cpe_matches:
        for image_cpe, vulnerability_cpe in all_cpe_matches:
            sev = vulnerability_cpe.severity
            if sev not in severity_matches:
                severity_matches[sev] = []
            severity_matches[sev].append((image_cpe, vulnerability_cpe))

        #context.data['all_cpe_matches'] = all_cpe_matches        
        context.data['severity_matches'] = severity_matches
        log.debug("context prep time: {}".format(time.time() - timer))

        return context
