from anchore_engine.db import AnalysisArtifact
from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.services.policy_engine.engine.policy.params import (
    CommaDelimitedNumberListParameter,
    CommaDelimitedStringListParameter,
    TriggerParameter,
    TypeValidator,
)
from anchore_engine.utils import ensure_str


class FileNotStoredTrigger(BaseTrigger):
    __trigger_name__ = "content_not_available"
    __description__ = (
        "Triggers if the /etc/passwd file is not present/stored in the evaluated image."
    )
    __params__ = None
    __msg__ = "Cannot locate /etc/passwd in image stored files archive: check analyzer settings."

    def evaluate(self, image_obj, context):
        if not context.data.get("passwd_entries"):
            self._fire()
        return


class PentryDenylistMixin(object):
    def exec_denylist(self, denylist_items, pentry_index, pentries_dict):
        """
        Process a denylist against pentries

        :param denylist_items: list of strings to check for in pentry locations
        :param pentry_index: item index in the pentry to check against, -1 means user-name, and None means entire entry
        :param pentries_dict: {'username': <array form of a pentry minus usename> }
        :return: list of match tuples where each tuple is (<matched candidate>, <entire matching pentry>)
        """
        matches = []
        for user, pentry in list(pentries_dict.items()):
            if pentry_index is not None:
                candidate = pentry[pentry_index] if pentry_index > 0 else user
            else:
                candidate = ":".join([user] + pentry)

            if candidate in denylist_items:
                matches.append((candidate, ":".join([user] + pentry)))
        return matches


class UsernameMatchDenyTrigger(BaseTrigger, PentryDenylistMixin):
    __trigger_name__ = "denylist_usernames"
    __msg_base__ = "Denylisted user "
    __description__ = "Triggers if specified username is found in the /etc/passwd file"
    
    user_denylist = CommaDelimitedStringListParameter(
        name="user_names",
        example_str="daemon,ftp",
        aliases=["usernameblacklist", "usernamedenylist"],
        description="List of usernames that will cause the trigger to fire if found in /etc/passwd.",
        is_required=True,
    )

    def evaluate(self, image_obj, context):
        if not context.data.get("passwd_entries"):
            return

        user_entries = context.data.get("passwd_entries")
        find_users = set(
            [x.strip() for x in self.user_denylist.value()]
            if self.user_denylist.value()
            else []
        )

        for username, pentry in self.exec_denylist(find_users, -1, user_entries):
            self._fire(
                msg=self.__msg_base__ + "'{}' found in image's /etc/passwd: pentry={}".format(
                    username, pentry
                )
            )

class UsernameMatchTrigger(UsernameMatchDenyTrigger, PentryDenylistMixin):
    __trigger_name__ = "blacklist_usernames"
    __msg_base__ = "Blacklisted user "

class UserIdMatchDenyTrigger(BaseTrigger, PentryDenylistMixin):
    __trigger_name__ = "denylist_userids"
    __msg_base__ = "Denylisted uid "
    __description__ = "Triggers if specified user id is found in the /etc/passwd file"

    user_id_denylist = CommaDelimitedNumberListParameter(
        name="user_ids",
        example_str="0,1",
        aliases=["useridblacklist", "useriddenylist"],
        description="List of userids (numeric) that will cause the trigger to fire if found in /etc/passwd.",
        is_required=True,
    )

    def evaluate(self, image_obj, context):
        if not context.data.get("passwd_entries"):
            return

        user_entries = context.data.get("passwd_entries")
        find_users = set(
            [str(x) for x in self.user_id_denylist.value()]
            if self.user_id_denylist.value()
            else []
        )

        for uid, pentry in self.exec_denylist(find_users, 1, user_entries):
            self._fire(
                msg=self.__msg_base__ + "'{}' found in image's /etc/passwd: pentry={}".format(
                    uid, str(pentry)
                )
            )

class UserIdMatchTrigger(UserIdMatchDenyTrigger, PentryDenylistMixin):
    __trigger_name__ = "blacklist_userids"    
    __msg_base__ = "Blacklisted uid "
    
class GroupIdMatchDenyTrigger(BaseTrigger, PentryDenylistMixin):
    __trigger_name__ = "denylist_groupids"
    __msg_base__ = "Denylisted gid "
    __description__ = "Triggers if specified group id is found in the /etc/passwd file"
    
    group_id_denylist = CommaDelimitedNumberListParameter(
        name="group_ids",
        example_str="999,20",
        description="List of groupids (numeric) that will cause the trigger ot fire if found in /etc/passwd.",
        is_required=True,
    )

    def evaluate(self, image_obj, context):
        if not context.data.get("passwd_entries"):
            return

        user_entries = context.data.get("passwd_entries")
        find_gid = set(
            [str(x) for x in self.group_id_denylist.value()]
            if self.group_id_denylist.value()
            else []
        )

        for gid, pentry in self.exec_denylist(find_gid, 2, user_entries):
            self._fire(
                msg=self.__msg_base__ + "'{}' found in image's /etc/passwd: pentry={}".format(
                    gid, str(pentry)
                )
            )

# For backward compatilbility only    
class GroupIdMatchTrigger(GroupIdMatchDenyTrigger, PentryDenylistMixin):
    __trigger_name__ = "blacklist_groupids"    
    __msg_base__ = "Blacklisted gid "
    
class ShellMatchDenyTrigger(BaseTrigger, PentryDenylistMixin):
    __trigger_name__ = "denylist_shells"
    __msg_base__ = "Denylisted shell "
    __aliases__ = ["shellmatch"]
    __description__ = "Triggers if specified login shell for any user is found in the /etc/passwd file"
    
    shell_denylist = CommaDelimitedStringListParameter(
        name="shells",
        example_str="/bin/bash,/bin/zsh",
        description="List of shell commands to denylist.",
        is_required=True,
    )

    def evaluate(self, image_obj, context):
        if not context.data.get("passwd_entries"):
            return

        user_entries = context.data.get("passwd_entries")
        find_shell = (
            set(self.shell_denylist.value()) if self.shell_denylist.value() else set()
        )

        for shell, pentry in self.exec_denylist(find_shell, 5, user_entries):
            self._fire(
                msg=self.__msg_base__ + "'{}' found in image's /etc/passwd: pentry={}".format(
                    shell, str(pentry)
                )
            )

        return

# For backward compatilbility only    
class ShellMatchTrigger(ShellMatchDenyTrigger, PentryDenylistMixin):
    __trigger_name__ = "blacklist_shells"    
    __msg_base__ = "Blacklisted shell "

class PEntryMatchDenyTrigger(BaseTrigger, PentryDenylistMixin):    
    __trigger_name__ = "denylist_full_entry"
    __msg_base__ = "Denylisted pentry "    
    __description__ = (
        "Triggers if entire specified passwd entry is found in the /etc/passwd file."
    )
    
    pentry_denylist = TriggerParameter(
        name="entry",
        example_str="ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin",
        description="Full entry to match in /etc/passwd.",
        validator=TypeValidator("string"),
        is_required=True,
    )

    def evaluate(self, image_obj, context):
        if not context.data.get("passwd_entries"):
            return

        user_entries = context.data.get("passwd_entries")
        denylisted = [self.pentry_denylist.value().strip()]

        for pentry, pentry in self.exec_denylist(denylisted, None, user_entries):
            self._fire(
                msg=self.__msg_base__ + "'{}' found in image's /etc/passwd: pentry={}".format(
                    pentry, str(pentry)
                )
            )

        return

# For backwards compatibility only    
class PEntryMatchTrigger(PEntryMatchDenyTrigger, PentryDenylistMixin):
    __trigger_name__ = "blacklist_full_entry"
    __msg_base__ = "Blacklisted pentry "


class FileparsePasswordGate(Gate):
    __gate_name__ = "passwd_file"
    __description__ = "Content checks for /etc/passwd for things like usernames, group ids, shells, or full entries."
    __triggers__ = [
        FileNotStoredTrigger,
        UsernameMatchTrigger,
        UserIdMatchTrigger,
        GroupIdMatchTrigger,
        ShellMatchTrigger,
        PEntryMatchTrigger,
        UsernameMatchDenyTrigger,
        UserIdMatchDenyTrigger,
        GroupIdMatchDenyTrigger,
        ShellMatchDenyTrigger,
        PEntryMatchDenyTrigger,        
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

        content_matches = image_obj.analysis_artifacts.filter(
            AnalysisArtifact.analyzer_id == "retrieve_files",
            AnalysisArtifact.analyzer_artifact == "file_content.all",
            AnalysisArtifact.analyzer_type == "base",
            AnalysisArtifact.artifact_key == "/etc/passwd",
        ).first()
        if content_matches:
            try:
                pentries = {}
                for line in ensure_str(content_matches.binary_value).splitlines():
                    line = line.strip()
                    pentry = line.split(":")
                    pentries[pentry[0]] = pentry[1:]
                context.data["passwd_entries"] = pentries
            except Exception as e:
                raise e

        return context
