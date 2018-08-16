from twisted.cred import checkers, credentials, error as credError
from twisted.internet import defer
from zope.interface import implementer

from anchore_engine.db import db_users
from anchore_engine.db import session_scope
from anchore_engine.subsys import logger

@implementer(checkers.ICredentialsChecker)
class AnchorePasswordChecker:
    credentialInterfaces = (credentials.IUsernamePassword,)

    def requestAvatarId(self, credentials):
        return self.requestAvatarId_db(credentials)

    def requestAvatarId_db(self, credentials):
        try:
            username = str(credentials.username, 'utf-8')

            with session_scope() as dbsession:
                user_record = db_users.get(username, session=dbsession)

            if not user_record:
                return defer.fail(credError.UnauthorizedLogin("Invalid user"))
            elif not user_record['active']:
                return defer.fail(credError.UnauthorizedLogin("Inactive user"))
            else:
                if user_record['password'] == str(credentials.password, 'utf-8'):
                    return defer.succeed(username.encode('utf8'))

            return defer.fail(credError.UnauthorizedLogin("Bad password"))
        except Exception as err:
            logger.exception('Error during auth')
            return defer.fail(credError.UnauthorizedLogin("Auth check exception - " + str(err)))

        return defer.fail(credError.UnauthorizedLogin("Unknown auth failure"))
