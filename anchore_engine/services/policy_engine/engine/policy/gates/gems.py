from anchore_engine.db import GemMetadata
from anchore_engine.services.policy_engine.engine.feeds.feeds import (
    feed_instance_by_name,
)
from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.services.policy_engine.engine.policy.params import (
    TriggerParameter,
    TypeValidator,
)
from anchore_engine.subsys import logger

# TODO; generalize these for any feed, with base classes and children per feed type

FEED_KEY = "gem"
GEM_MATCH_KEY = "matched_feed_gems"
GEM_LIST_KEY = "gems"


class NotLatestTrigger(BaseTrigger):
    __trigger_name__ = "newer_version_found_in_feed"
    __description__ = "Triggers if an installed GEM is not the latest version according to GEM data feed."

    def evaluate(self, image_obj, context):
        """
        Fire for any gem in the image that is in the official gem feed but is not the latest version.
        Mutually exclusive to GEMNOTOFFICIAL and GEMBADVERSION

        """
        feed_gems = context.data.get(GEM_MATCH_KEY)
        img_gems = context.data.get(GEM_LIST_KEY)

        if not feed_gems or not img_gems:
            return

        feed_names = {p.name: p.latest for p in feed_gems}

        for gem, versions in list(img_gems.items()):
            if gem not in feed_names:
                continue  # Not an official

            for v in versions:
                if v and v != feed_names.get(gem):
                    self._fire(
                        msg="Package ({}) version ({}) installed but is not the latest version ({})".format(
                            gem, v, feed_names[gem]
                        )
                    )


class NotOfficialTrigger(BaseTrigger):
    __trigger_name__ = "not_found_in_feed"
    __description__ = "Triggers if an installed GEM is not in the official GEM database, according to GEM data feed."

    def evaluate(self, image_obj, context):
        """
        Fire for any gem that is not in the official gem feed data set.

        Mutually exclusive to GEMNOTLATEST and GEMBADVERSION

        :param image_obj:
        :param context:
        :return:
        """

        feed_gems = context.data.get(GEM_MATCH_KEY)
        img_gems = context.data.get(GEM_LIST_KEY)

        if not feed_gems or not img_gems:
            return

        feed_names = {p.name: p.versions_json for p in feed_gems}

        for gem in list(img_gems.keys()):
            if gem not in feed_names:
                self._fire(
                    msg="GEMNOTOFFICIAL Package ("
                    + str(gem)
                    + ") in container but not in official GEM feed."
                )


class BadVersionTrigger(BaseTrigger):
    __trigger_name__ = "version_not_found_in_feed"
    __description__ = "Triggers if an installed GEM version is not listed in the official GEM feed as a valid version."

    def evaluate(self, image_obj, context):
        """
        Fire for any gem that is in the official gem set but is not one of the official versions.

        Mutually exclusive to GEMNOTOFFICIAL and GEMNOTLATEST

        :param image_obj:
        :param context:
        :return:
        """
        feed_gems = context.data.get(GEM_MATCH_KEY)
        img_gems = context.data.get(GEM_LIST_KEY)

        if not feed_gems or not img_gems:
            return

        feed_names = {p.name: p.versions_json for p in feed_gems}

        for gem, versions in list(img_gems.items()):
            if gem not in feed_names:
                continue

            non_official_versions = set(versions).difference(
                set(feed_names.get(gem, []))
            )
            for v in non_official_versions:
                self._fire(
                    msg="GEMBADVERSION Package ("
                    + gem
                    + ") version ("
                    + v
                    + ") installed but version is not in the official feed for this package ("
                    + str(feed_names.get(gem, ""))
                    + ")"
                )


class BlacklistedGemTrigger(BaseTrigger):
    __trigger_name__ = "blacklist"
    __description__ = "Triggers if the evaluated image has a GEM package installed that matches the specified name and version."

    name = TriggerParameter(
        validator=TypeValidator("string"),
        name="name",
        is_required=True,
        description="Gem name to blacklist.",
        example_str="time_diff",
        sort_order=1,
    )
    version = TriggerParameter(
        validator=TypeValidator("string"),
        name="version",
        is_required=False,
        description="Optional version to blacklist specifically.",
        example_str="0.2.9",
        sort_order=2,
    )

    def evaluate(self, image_obj, context):
        """
        Fire for any gem that is on the blacklist with a full name + version match
        :param image_obj:
        :param context:
        :return:
        """
        gems = image_obj.get_packages_by_type("gem")
        if not gems:
            return

        pkgs = context.data.get(GEM_LIST_KEY)
        if not pkgs:
            return

        name = self.name.value()
        version = self.version.value(default_if_none=None)

        if name in pkgs:
            if version and version in pkgs.get(name, []):
                self._fire(msg="Gem Package is blacklisted: " + name + "-" + version)
            elif version is None:
                self._fire(msg="Gem Package is blacklisted: " + name)


class NoFeedTrigger(BaseTrigger):
    __trigger_name__ = "feed_data_unavailable"
    __description__ = "Triggers if anchore does not have access to the GEM data feed."
    __msg__ = "Gem packages are present but the anchore gem feed is not available - will be unable to perform checks that require feed data"

    def evaluate(self, image_obj, context):
        try:
            feed_meta = feed_instance_by_name("packages").group_by_name(FEED_KEY)
            if feed_meta and feed_meta.last_sync:
                return
        except Exception as e:
            logger.exception(
                "Error determining feed presence for gems. Defaulting to firing trigger"
            )

        self._fire()
        return


class GemCheckGate(Gate):
    __gate_name__ = "ruby_gems"
    __description__ = "Ruby Gem Checks"
    __triggers__ = [
        NotLatestTrigger,
        NotOfficialTrigger,
        BadVersionTrigger,
        BlacklistedGemTrigger,
        NoFeedTrigger,
    ]

    def prepare_context(self, image_obj, context):
        """
        Prep the gem names and versions
        :rtype:
        :param image_obj:
        :param context:
        :return:
        """

        db_gems = image_obj.get_packages_by_type("gem")
        if not db_gems:
            return context

        # context.data[GEM_LIST_KEY] = {p.name: p.versions_json for p in image_obj.gems}

        # update to handle multiple records with the same version (but in different locations)
        gem_list_key_data = {}
        for p in db_gems:
            if p.name not in gem_list_key_data:
                gem_list_key_data[p.name] = []
            gem_list_key_data[p.name].append(p.version)

        context.data[GEM_LIST_KEY] = gem_list_key_data
        context.data[GEM_MATCH_KEY] = []
        gems = list(context.data[GEM_LIST_KEY].keys())

        # Use a chunked fetch approach to avoid a single large in() statement with 1000+ keys
        chunks = [gems[i : i + 100] for i in range(0, len(gems), 100)]
        for key_range in chunks:
            context.data[GEM_MATCH_KEY] += (
                context.db.query(GemMetadata)
                .filter(GemMetadata.name.in_(key_range))
                .all()
            )

        return context
