from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger
from anchore_engine.services.policy_engine.engine.policy.params import CommaDelimitedNumberListParameter, CommaDelimitedStringListParameter, TriggerParameter, TypeValidator
from anchore_engine.db import AnalysisArtifact


class FileNotStoredTrigger(BaseTrigger):
    __trigger_name__ = 'content_not_available'
    __description__ = 'Triggers if the /etc/passwd file is not present/stored in the evaluated image.'
    __params__ = None
    __msg__ = 'Cannot locate /etc/passwd in image stored files archive: check analyzer settings.'

    def evaluate(self, image_obj, context):
        if not context.data.get('passwd_entries'):
            self._fire()
        return


class PentryBlacklistMixin(object):
    def exec_blacklist(self, blacklist_items, pentry_index, pentries_dict):
        """
        Process a blacklist against pentries

        :param blacklist_items: list of strings to check for in pentry locations
        :param pentry_index: item index in the pentry to check against, -1 means user-name, and None means entire entry
        :param pentries_dict: {'username': <array form of a pentry minus usename> }
        :return: list of match tuples where each tuple is (<matched candidate>, <entire matching pentry>)
        """
        matches = []
        for user, pentry in list(pentries_dict.items()):
            if pentry_index is not None:
                candidate = pentry[pentry_index] if pentry_index > 0 else user
            else:
                candidate = ':'.join([user] + pentry)

            if candidate in blacklist_items:
                matches.append((candidate, ':'.join([user] + pentry)))
        return matches


class UsernameMatchTrigger(BaseTrigger, PentryBlacklistMixin):
    __trigger_name__ = 'blacklist_usernames'
    __description__ = 'Triggers if specified username is found in the /etc/passwd file'

    user_blacklist = CommaDelimitedStringListParameter(name='user_names', example_str='daemon,ftp', aliases=['usernameblacklist'], description='List of usernames that will cause the trigger to fire if found in /etc/passwd.', is_required=True)

    def evaluate(self, image_obj, context):
        if not context.data.get('passwd_entries'):
            return

        user_entries = context.data.get('passwd_entries')
        find_users = set([x.strip() for x in self.user_blacklist.value()] if self.user_blacklist.value() else [])

        for username, pentry in self.exec_blacklist(find_users, -1, user_entries):
            self._fire(msg="Blacklisted user '{}' found in image's /etc/passwd: pentry={}".format(username, pentry))


class UserIdMatchTrigger(BaseTrigger, PentryBlacklistMixin):
    __trigger_name__ = 'blacklist_userids'
    __description__ = 'Triggers if specified user id is found in the /etc/passwd file'

    user_id_blacklist = CommaDelimitedNumberListParameter(name='user_ids', example_str='0,1', aliases=['useridblacklist'], description='List of userids (numeric) that will cause the trigger to fire if found in /etc/passwd.', is_required=True)

    def evaluate(self, image_obj, context):
        if not context.data.get('passwd_entries'):
            return

        user_entries = context.data.get('passwd_entries')
        find_users = set([str(x) for x in self.user_id_blacklist.value()] if self.user_id_blacklist.value() else [])

        for uid, pentry in self.exec_blacklist(find_users, 1, user_entries):
            self._fire(msg="Blacklisted uid '{}' found in image's /etc/passwd: pentry={}".format(uid, str(pentry)))


class GroupIdMatchTrigger(BaseTrigger, PentryBlacklistMixin):
    __trigger_name__ = 'blacklist_groupids'
    __description__ = 'Triggers if specified group id is found in the /etc/passwd file'

    group_id_blacklist = CommaDelimitedNumberListParameter(name='group_ids', example_str='999,20', description='List of groupids (numeric) that will cause the trigger ot fire if found in /etc/passwd.', is_required=True)

    def evaluate(self, image_obj, context):
        if not context.data.get('passwd_entries'):
            return

        user_entries = context.data.get('passwd_entries')
        find_gid = set([str(x) for x in self.group_id_blacklist.value()] if self.group_id_blacklist.value() else [])

        for gid, pentry in self.exec_blacklist(find_gid, 2, user_entries):
            self._fire(msg="Blacklisted gid '{}' found in image's /etc/passwd: pentry={}".format(gid, str(pentry)))


class ShellMatchTrigger(BaseTrigger, PentryBlacklistMixin):
    __trigger_name__ = 'blacklist_shells'
    __aliases__ = ['shellmatch']
    __description__ = 'Triggers if specified login shell for any user is found in the /etc/passwd file'

    shell_blacklist = CommaDelimitedStringListParameter(name='shells', example_str='/bin/bash,/bin/zsh', description='List of shell commands to blacklist.', is_required=True)

    def evaluate(self, image_obj, context):
        if not context.data.get('passwd_entries'):
            return

        user_entries = context.data.get('passwd_entries')
        find_shell = set(self.shell_blacklist.value()) if self.shell_blacklist.value() else set()

        for shell, pentry in self.exec_blacklist(find_shell, 5, user_entries):
            self._fire(msg="Blacklisted shell '{}' found in image's /etc/passwd: pentry={}".format(shell, str(pentry)))

        return


class PEntryMatchTrigger(BaseTrigger, PentryBlacklistMixin):
    __trigger_name__ = 'blacklist_full_entry'
    __description__ = 'Triggers if entire specified passwd entry is found in the /etc/passwd file.'

    pentry_blacklist = TriggerParameter(name='entry', example_str='ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin', description='Full entry to match in /etc/passwd.', validator=TypeValidator('string'), is_required=True)

    def evaluate(self, image_obj, context):
        if not context.data.get('passwd_entries'):
            return

        user_entries = context.data.get('passwd_entries')
        blacklisted = [self.pentry_blacklist.value().strip()]

        for pentry, pentry in self.exec_blacklist(blacklisted, None, user_entries):
            self._fire(msg="Blacklisted pentry '{}' found in image's /etc/passwd: pentry={}".format(pentry, str(pentry)))

        return


class FileparsePasswordGate(Gate):
    __gate_name__ = 'passwd_file'
    __description__ = 'Content checks for /etc/passwd for things like usernames, group ids, shells, or full entries.'
    __triggers__ = [
        FileNotStoredTrigger,
        UsernameMatchTrigger,
        UserIdMatchTrigger,
        GroupIdMatchTrigger,
        ShellMatchTrigger,
        PEntryMatchTrigger,
    ]

    def prepare_context(self, image_obj, context):
        """
        prepare the context by extracting the /etc/passwd content for the image from the analysis artifacts list if it is found.
        loads from the db.

        This is an optimization and could removed, but if removed the triggers should be updated to do the queries directly.

        :rtype:
        :param image_obj:
        :param context:
        :return:
        """

        content_matches = image_obj.analysis_artifacts.filter(AnalysisArtifact.analyzer_id == 'retrieve_files', AnalysisArtifact.analyzer_artifact == 'file_content.all', AnalysisArtifact.analyzer_type == 'base', AnalysisArtifact.artifact_key == '/etc/passwd').first()
        if content_matches:
            try:
                pentries = {}
                for line in str(content_matches.binary_value).splitlines():
                    line = line.strip()
                    pentry = line.split(':')
                    pentries[pentry[0]] = pentry[1:]
                context.data['passwd_entries'] = pentries
            except Exception as e:
                raise e

        return context