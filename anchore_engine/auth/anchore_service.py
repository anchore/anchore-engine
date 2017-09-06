from zope.interface import implements

from twisted.cred import checkers, credentials, error as credError
from twisted.internet import defer
from zope.interface import implements

from anchore_engine.db import db_users
from anchore_engine.db import session_scope

class AnchorePasswordChecker:
    implements(checkers.ICredentialsChecker)
    credentialInterfaces = (credentials.IUsernamePassword,)

    def requestAvatarId(self, credentials):
        return(self.requestAvatarId_db(credentials))

    def requestAvatarId_db(self, credentials):
        try:
            username = credentials.username

            with session_scope() as dbsession:
                user_record = db_users.get(username, session=dbsession)

            if not user_record:
                return defer.fail(credError.UnauthorizedLogin("Invalid user"))
            else:
                #from passlib.hash import pbkdf2_sha256
                #hashpw = user_record['password']
                #if pbkdf2_sha256.verify(credentials.password, hashpw):
                if user_record['password'] == credentials.password:
                    return(defer.succeed(username))

            return defer.fail(credError.UnauthorizedLogin("Bad password"))
        except Exception as err:
            return defer.fail(credError.UnauthorizedLogin("Auth check exception - " + str(err)))

        return defer.fail(credError.UnauthorizedLogin("Unknown auth failure"))

def initialize():
    return(True)

