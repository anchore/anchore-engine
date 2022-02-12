from __future__ import annotations

import datetime
import re
from abc import ABC, abstractmethod
from collections import OrderedDict, namedtuple

from anchore_engine.db.entities.common import anchore_now_datetime
from anchore_engine.services.policy_engine.engine.policy.bundles.trigger_matches import (
    WhitelistedTriggerMatch,
)
from anchore_engine.services.policy_engine.engine.policy.gates import AnchoreSecGate
from anchore_engine.subsys import logger
from anchore_engine.util.matcher import is_match, regexify
from anchore_engine.util.time import rfc3339str_to_datetime


class IWhitelistItemIndex(ABC):
    """
    A data structure to lookup potential whitelist items for a given gate output
    """

    @abstractmethod
    def add(self, item):
        """
        Add the whitelist item to the index for lookup

        :param item:
        :return:
        """
        ...

    @abstractmethod
    def candidates_for(self, decision_match):
        """
        Return whitelist items that may match the decision. Depending on the implementation may be an exact or fuzzy match.

        :param decision_match:
        :return: list of ExecutableWhitelistItem objects
        """
        ...


class HybridTriggerIdKeyedItemIndex(IWhitelistItemIndex):
    """
    An index that has a primary keyed lookup and a secondary list for unkeyed entries.

    Each gate has its own index composed of a keyed index and an array for any whitelist items that are not triggerid specific
    """

    GateItemIndex = namedtuple("GateItemIndex", ["keyed", "unkeyed"])

    def __init__(self, item_key_fn=None, match_key_fn=None):
        self.gate_keys = OrderedDict()
        self.key_fn = item_key_fn
        self.match_key_fn = match_key_fn

    def add(self, item):
        key = None
        if self.key_fn:
            key = self.key_fn(item)

        gate_name = item.gate.lower()

        if gate_name not in self.gate_keys:
            self.gate_keys[gate_name] = HybridTriggerIdKeyedItemIndex.GateItemIndex(
                keyed=OrderedDict(), unkeyed=[]
            )

        if not key:
            self.gate_keys[gate_name].unkeyed.append(item)
        else:
            if key not in self.gate_keys[gate_name].keyed:
                self.gate_keys[gate_name].keyed[key] = []

            self.gate_keys[gate_name].keyed[key].append(item)

    def candidates_for(self, decision):
        gate_entry = self.gate_keys.get(
            decision.match.trigger.gate_cls.__gate_name__.lower()
        )
        if not gate_entry:
            return []

        if self.match_key_fn:
            key = self.match_key_fn(decision)
        else:
            key = None

        if key:
            keyed = gate_entry.keyed.get(key, [])
        else:
            keyed = []

        unkeyed = gate_entry.unkeyed
        return keyed + unkeyed


class StandardCVETriggerIdKey(object):
    cve_trigger_id_regex = re.compile(r"([A-Za-z0-9\-])+\+\*")
    supported_gates = [AnchoreSecGate.__gate_name__.lower()]

    @classmethod
    def whitelist_item_key(cls, item):
        """
        Return a key value for the item if the item is an ANCHORESEC gate with trigger_id of the
        form <CVE>+<pkg> where <pkg> may be '*'. Else return None

        :param item: a whitelist item json
        :return: a key for a dictionary or None if not hashable/indexable
        """

        if item.gate.lower() in cls.supported_gates and cls.cve_trigger_id_regex.match(
            item.trigger_id
        ):
            return cls.anchoresec_trigger_id_to_parts(item.trigger_id)
        return None

    @classmethod
    def anchoresec_trigger_id_to_parts(cls, trigger_id):
        pieces = trigger_id.split("+", 1)
        if len(pieces) > 1:
            cve, pkg = pieces
            # pkg is either a specific pkg or a wildcard
            return cve
        return trigger_id

    @classmethod
    def decision_item_key(cls, decision):
        gate = decision.match.trigger.gate_cls.__gate_name__.lower()
        if gate in cls.supported_gates:
            return cls.anchoresec_trigger_id_to_parts(decision.match.id)
        else:
            return decision.match.id

    @classmethod
    def noop_key(cls, item):
        """
        Always return None, so no keyed lookups are done.

        :param item:
        :return:
        """
        return None


class ExecutableWhitelistItem(object):
    """
    A single whitelist item to evaluate against a single gate trigger instance
    """

    def __init__(self, item_json, parent):
        self.id = item_json.get("id")
        self.gate = item_json.get("gate").lower()
        self.trigger_id = item_json.get("trigger_id")
        expires_on_str = item_json.get("expires_on", "")
        if expires_on_str:
            try:
                self.expires_on = rfc3339str_to_datetime(expires_on_str)
            except Exception as err:
                logger.exception("Failed to parse")
                raise err
        self.parent_whitelist = parent

    def is_expired(self):
        now_utc = anchore_now_datetime().replace(tzinfo=datetime.timezone.utc)
        return (
            hasattr(self, "expires_on")
            and self.expires_on
            and now_utc >= self.expires_on
        )

    def execute(self, trigger_match):
        """
        Return a processed instance
        :param trigger_inst: the trigger instance to check
        :return: a WhitelistedTriggerInstance or a TriggerInstance depending on if the items match
        """
        # If this whitelist rule is expired, we do not search for any matches
        # When expires_on is parsed it's translated to UTC, so we must do the same for getting the current time
        # so that we can compare them
        if self.is_expired():
            return trigger_match

        if hasattr(trigger_match, "is_whitelisted") and trigger_match.is_whitelisted():
            return trigger_match

        if hasattr(trigger_match, "id"):
            if self.matches(trigger_match):
                return WhitelistedTriggerMatch(trigger_match, self)
            else:
                return trigger_match

    def matches(self, fired_trigger_obj):
        # TODO: add alias checks here for backwards compat

        return (
            self.gate == fired_trigger_obj.trigger.gate_cls.__gate_name__.lower()
            and (
                self.trigger_id == fired_trigger_obj.id
                or is_match(regexify, self.trigger_id, fired_trigger_obj.id)
            )
        )

    def json(self):
        return {"id": self.id, "gate": self.gate, "trigger_id": self.trigger_id}
