from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger, LifecycleStates
from anchore_engine.services.policy_engine.engine.policy.params import NameVersionStringListParameter, CommaDelimitedStringListParameter
from anchore_engine.db import NpmMetadata
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.services.policy_engine.engine.feeds import DataFeeds

log = get_logger()

FEED_KEY = 'npm'
NPM_LISTING_KEY = 'npms'
NPM_MATCH_KEY = 'matched_feed_npms'


class NotLatestTrigger(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'npmnotlatest'
    __description__ = 'triggers if an installed NPM is not the latest version according to NPM data feed'

    def evaluate(self, image_obj, context):
        """
        Fire for any npm in the image that is in the official npm feed but is not the latest version.
        Mutually exclusive to NPMNOTOFFICIAL and NPMBADVERSION

        """
        feed_npms = context.data.get(NPM_MATCH_KEY)
        img_npms = context.data.get(NPM_LISTING_KEY)

        if feed_npms or not img_npms:
            return

        feed_names = {p.name: p.latest for p in feed_npms}

        for npm, versions in list(img_npms.items()):
            if npm not in feed_names:
                continue # Not an official

            for v in versions:
                if v and v != feed_names.get(npm):
                    self._fire(msg="NPMNOTLATEST Package ("+npm+") version ("+v+") installed but is not the latest version ("+feed_names[npm]['latest']+")")


class NotOfficialTrigger(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'npmnotofficial'
    __description__ = 'triggers if an installed NPM is not in the official NPM database, according to NPM data feed'

    def evaluate(self, image_obj, context):
        """
        Fire for any npm that is not in the official npm feed data set.

        Mutually exclusive to NPMNOTLATEST and NPMBADVERSION

        :param image_obj:
        :param context:
        :return:
        """

        feed_npms = context.data.get(NPM_MATCH_KEY)
        img_npms = context.data.get(NPM_LISTING_KEY)

        if feed_npms or not img_npms:
            return

        feed_names = {p.name: p.versions_json for p in feed_npms}

        for npm in list(img_npms.keys()):
            if npm not in feed_names:
                self._fire(msg="NPMNOTOFFICIAL Package ("+str(npm)+") in container but not in official NPM feed.")


class BadVersionTrigger(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'npmbadversion'
    __description__ = 'triggers if an installed NPM version is not listed in the official NPM feed as a valid version'

    def evaluate(self, image_obj, context):
        """
        Fire for any npm that is in the official npm set but is not one of the official versions.

        Mutually exclusive to NPMNOTOFFICIAL and NPMNOTLATEST

        :param image_obj:
        :param context:
        :return:
        """
        feed_npms = context.data.get(NPM_MATCH_KEY)
        img_npms = context.data.get(NPM_LISTING_KEY)

        if feed_npms or not img_npms:
            return

        feed_names = {p.name: p.versions_json for p in feed_npms}

        for npm, versions in list(img_npms.items()):
            if npm not in feed_names:
                continue

            non_official_versions = set(versions).difference(set(feed_names.get(npm, [])))
            for v in non_official_versions:
                self._fire(msg="NPMBADVERSION Package ("+npm+") version ("+v+") installed but version is not in the official feed for this package ("+str(feed_names.get(npm, '')) + ")")


class PkgFullMatchTrigger(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'npmpkgfullmatch'
    __description__ = 'triggers if the evaluated image has an NPM package installed that matches one in the list given as a param (package_name|vers)'

    blacklist_names = NameVersionStringListParameter(name='blacklist_npmfullmatch', example_str='json|1.0.1,datetime|1.1.1', description='List of name|version matches for full package match on blacklist')

    def evaluate(self, image_obj, context):
        """
        Fire for any npm that is on the blacklist with a full name + version match
        :param image_obj:
        :param context:
        :return:
        """
        npms = image_obj.npms
        if not npms:
            return

        pkgs = context.data.get(NPM_LISTING_KEY)
        if not pkgs:
            return

        match_versions = self.blacklist_names.value() if self.blacklist_names.value() else {}
        for pkg, vers in list(match_versions.items()):
            try:
                if pkg in pkgs and vers in pkgs.get(pkg, []):
                    self._fire(msg='NPMPKGFULLMATCH Package is blacklisted: '+pkg+"-"+vers)
            except Exception as e:
                continue


class PkgNameMatchTrigger(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'npmpkgnamematch'
    __description__ = 'triggers if the evaluated image has an NPM package installed that matches one in the list given as a param (package_name)'

    npmname_blacklist = CommaDelimitedStringListParameter(name='blacklist_npmnamematch', example_str='json,moment', description='List of name strings to blacklist npm package names against')

    def evaluate(self, image_obj, context):
        npms = image_obj.npms
        if not npms:
            return

        pkgs = context.data.get(NPM_LISTING_KEY)
        if not pkgs:
            return

        match_names = self.npmname_blacklist.value() if self.npmname_blacklist.value() else []

        for match_val in match_names:
            if match_val and match_val in pkgs:
                self._fire(msg='NPMPKGNAMEMATCH Package is blacklisted: ' + match_val)


class NoFeedTrigger(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'npmnofeed'
    __description__ = 'triggers if anchore does not have access to the NPM data feed'
    __msg__ = "NPMNOFEED NPM packages are present but the anchore NPM feed is not available - will be unable to perform checks that require feed data"

    def evaluate(self, image_obj, context):
        try:
            feed_meta = DataFeeds.instance().packages.group_by_name(FEED_KEY)
            if feed_meta and feed_meta[0].last_sync:
                return
        except Exception as e:
            log.exception('Error determining feed presence for npms. Defaulting to firing trigger')

        self._fire()
        return


class NpmCheckGate(Gate):
    __lifecycle_state__ = LifecycleStates.deprecated
    __superceded_by__ = 'npms'
    __gate_name__ = 'npmcheck'
    __description__ = 'NPM Checks'
    __triggers__ = [
        NotLatestTrigger,
        NotOfficialTrigger,
        BadVersionTrigger,
        PkgFullMatchTrigger,
        PkgNameMatchTrigger,
        NoFeedTrigger
    ]

    def prepare_context(self, image_obj, context):
        """
        Prep the npm names and versions
        :rtype:
        :param image_obj:
        :param context:
        :return:
        """

        if not image_obj.npms:
            return context

        context.data[NPM_LISTING_KEY] = {p.name: p.versions_json for p in image_obj.npms}

        npms = list(context.data[NPM_LISTING_KEY].keys())
        context.data[NPM_MATCH_KEY] = []
        chunks = [npms[i: i+100] for i in range(0, len(npms), 100)]
        for key_range in chunks:
            context.data[NPM_MATCH_KEY] += context.db.query(NpmMetadata).filter(NpmMetadata.name.in_(key_range)).all()

        return context
