"""
Entities for the catalog service including services, users, images, etc. Pretty much everything except image analysis data

"""
import json

from sqlalchemy import Column, Integer, String, Boolean, BigInteger
from sqlalchemy import inspect

from .common import Base, anchore_now

class Anchore(Base):
    __tablename__ = 'anchore'

    service_version = Column(String, primary_key=True)
    db_version = Column(String, primary_key=True)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    record_state_key = Column(String, default="active")
    record_state_val = Column(String)

    scanner_version = Column(String)

    def json(self):
        thedata = dict((key, value) for key, value in vars(self).iteritems() if not key.startswith('_'))
        return (json.dumps(thedata))

    def update(self, inobj):
        for a in inobj.keys():
            if hasattr(self, a):
                setattr(self, a, inobj[a])

    def __repr__(self):
        return "service_version='%s' db_version='%s' scanner_version='%s'" % (
        self.service_version, self.db_version, self.scanner_version)


class ArchiveDocument(Base):
    __tablename__ = 'archive_document'

    bucket = Column(String, primary_key=True)
    archiveId = Column(String, primary_key=True)
    userId = Column(String, primary_key=True)
    documentName = Column(String, primary_key=True)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    record_state_key = Column(String, default="active")
    record_state_val = Column(String)
    jsondata = Column(String)

    def json(self):
        thedata = dict((key, value) for key, value in vars(self).iteritems() if not key.startswith('_'))
        return (json.dumps(thedata))

    def update(self, inobj):
        for a in inobj.keys():
            if hasattr(self, a):
                setattr(self, a, inobj[a])

    def __repr__(self):
        return "userId='%s'" % (self.userId)


class User(Base):
    __tablename__ = 'users'

    userId = Column(String, primary_key=True)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    record_state_key = Column(String, default="active")
    record_state_val = Column(String)
    password = Column(String)
    email = Column(String)
    acls = Column(String)
    active = Column(Boolean)

    def json(self):
        thedata = dict((key, value) for key, value in vars(self).iteritems() if not key.startswith('_'))
        return (json.dumps(thedata))

    def update(self, inobj):
        for a in inobj.keys():
            if hasattr(self, a):
                setattr(self, a, inobj[a])

    def __repr__(self):
        return "userId='%s'" % (self.userId)


class EventLog(Base):
    __tablename__ = 'eventlog'

    hostId = Column(String, primary_key=True)
    service_name = Column(String, primary_key=True)
    message = Column(String, primary_key=True)
    level = Column(String, primary_key=True)
    message_ts = Column(Integer, default=anchore_now)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    record_state_key = Column(String, default="active")
    record_state_val = Column(String)
    detail = Column(String)

    def json(self):
        thedata = dict((key, value) for key, value in vars(self).iteritems() if not key.startswith('_'))
        return (json.dumps(thedata))

    def update(self, inobj):
        for a in inobj.keys():
            if hasattr(self, a):
                setattr(self, a, inobj[a])

    def __repr__(self):
        return "hostId='%s' message='%s' level='%s'" % (self.hostId, self.message, self.level)


class QueueItem(Base):
    __tablename__ = 'queues'

    queueId = Column(String, primary_key=True)
    userId = Column(String, primary_key=True)
    dataId = Column(String, primary_key=True)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    record_state_key = Column(String, default="active")
    record_state_val = Column(String)
    data = Column(String)
    tries = Column(Integer)
    max_tries = Column(Integer)

    def json(self):
        thedata = dict((key, value) for key, value in vars(self).iteritems() if not key.startswith('_'))
        return (json.dumps(thedata))

    def update(self, inobj):
        for a in inobj.keys():
            if hasattr(self, a):
                setattr(self, a, inobj[a])

    def __repr__(self):
        return "queueId='%s'" % (self.queueId)


if True:
    class QueueMeta(Base):
        __tablename__ = 'queuemeta'

        queueName = Column(String, primary_key=True)
        userId = Column(String, primary_key=True)
        created_at = Column(Integer, default=anchore_now)
        last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
        record_state_key = Column(String, default="active")
        record_state_val = Column(String)
        qlen = Column(BigInteger, default=0)

        def json(self):
            thedata = dict((key, value) for key, value in vars(self).iteritems() if not key.startswith('_'))
            return (json.dumps(thedata))

        def update(self, inobj):
            for a in inobj.keys():
                if hasattr(self, a):
                    setattr(self, a, inobj[a])

        def __repr__(self):
            return "queueName='%s'" % (self.queueName)


    class Queue(Base):
        __tablename__ = 'queue'

        queueId = Column(BigInteger, primary_key=True, autoincrement=True)
        userId = Column(String, primary_key=True)
        queueName = Column(String, primary_key=True)
        created_at = Column(Integer, default=anchore_now)
        last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
        record_state_key = Column(String, default="active")
        record_state_val = Column(String)
        popped = Column(Boolean, default=False)
        priority = Column(Boolean, default=False)
        data = Column(String, default='{}')
        dataId = Column(String)
        tries = Column(Integer, default=0)
        max_tries = Column(Integer, default=0)

        def json(self):
            thedata = dict((key, value) for key, value in vars(self).iteritems() if not key.startswith('_'))
            return (json.dumps(thedata))

        def update(self, inobj):
            for a in inobj.keys():
                if hasattr(self, a):
                    setattr(self, a, inobj[a])

        def __repr__(self):
            return "queueId='%s'" % (self.queueId)


class Subscription(Base):
    __tablename__ = 'subscriptions'

    subscription_id = Column(String, primary_key=True)
    userId = Column(String, primary_key=True)
    subscription_type = Column(String, primary_key=True)
    subscription_key = Column(String, primary_key=True)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    record_state_key = Column(String, default="active")
    record_state_val = Column(String)
    subscription_value = Column(String)
    active = Column(Boolean)

    def make(self):
        ret = {}
        m = inspect(self)
        for c in m.attrs:
            ret[c.key] = None
        return (ret)

    def json(self):
        thedata = dict((key, value) for key, value in vars(self).iteritems() if not key.startswith('_'))
        return (json.dumps(thedata))

    def update(self, inobj):
        for a in inobj.keys():
            if hasattr(self, a):
                setattr(self, a, inobj[a])

    def __repr__(self):
        return "userId='%s' subscription_type='%s' subscription_key='%s'" % (
        self.userId, self.subscription_type, self.subscription_key)


class CatalogImage(Base):
    __tablename__ = "catalog_image"

    imageDigest = Column(String, primary_key=True)
    userId = Column(String, primary_key=True)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    record_state_key = Column(String, default="active")
    record_state_val = Column(String)

    image_type = Column(String)
    analysis_status = Column(String)
    image_status = Column(String)

    def make(self):
        ret = {}

        m = inspect(self)
        for c in m.attrs:
            ret[c.key] = None

        return (ret)

    def json(self):
        thedata = dict((key, value) for key, value in vars(self).iteritems() if not key.startswith('_'))
        return (json.dumps(thedata))

    def update(self, inobj):
        for a in inobj.keys():
            if hasattr(self, a):
                setattr(self, a, inobj[a])

    def __repr__(self):
        return "imageDigest='%s'" % (self.imageDigest)


class CatalogImageDocker(Base):
    __tablename__ = "catalog_image_docker"

    imageDigest = Column(String, primary_key=True)
    userId = Column(String, primary_key=True)
    registry = Column(String, primary_key=True)
    repo = Column(String, primary_key=True)
    tag = Column(String, primary_key=True)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    record_state_key = Column(String, default="active")
    record_state_val = Column(String)

    digest = Column(String)
    imageId = Column(String)
    dockerfile = Column(String)

    def make(self):
        ret = {}
        m = inspect(self)
        for c in m.attrs:
            ret[c.key] = None
        return (ret)

    def json(self):
        thedata = dict((key, value) for key, value in vars(self).iteritems() if not key.startswith('_'))
        return (json.dumps(thedata))

    def update(self, inobj):
        for a in inobj.keys():
            if hasattr(self, a):
                setattr(self, a, inobj[a])

    def __repr__(self):
        return "digest='%s'" % (self.digest)


class PolicyBundle(Base):
    __tablename__ = 'policy_bundle'

    policyId = Column(String, primary_key=True)
    userId = Column(String, primary_key=True)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    record_state_key = Column(String, default="active")
    record_state_val = Column(String)
    active = Column(Boolean)
    policy_source = Column(String, default="local")

    # policybundle = Column(String)

    def json(self):
        thedata = dict((key, value) for key, value in vars(self).iteritems() if not key.startswith('_'))
        return (json.dumps(thedata))

    def update(self, inobj):
        for a in inobj.keys():
            if hasattr(self, a):
                setattr(self, a, inobj[a])

    def __repr__(self):
        return "policyId='%s'" % (self.policyId)


class PolicyEval(Base):
    __tablename__ = 'policy_eval'

    userId = Column(String, primary_key=True)
    imageDigest = Column(String, primary_key=True)
    tag = Column(String, primary_key=True)
    policyId = Column(String, primary_key=True)
    final_action = Column(String, primary_key=True)
    created_at = Column(Integer, primary_key=True)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    record_state_key = Column(String, default="active")
    record_state_val = Column(String)

    evalId = Column(String)
    policyeval = Column(String)

    def make(self):
        ret = {}
        m = inspect(self)
        for c in m.attrs:
            ret[c.key] = None
        return (ret)

    def content_compare(self, other):
        selfdata = dict((key, value) for key, value in vars(self).iteritems() if not key.startswith('_'))
        otherdata = dict((key, value) for key, value in vars(other).iteritems() if not key.startswith('_'))
        for k in ['userId', 'imageDigest', 'tag', 'policyId', 'final_action']:
            try:
                if selfdata[k] != otherdata[k]:
                    return (False)
            except:
                return (False)
        return (True)

    def json(self):
        thedata = dict((key, value) for key, value in vars(self).iteritems() if not key.startswith('_'))
        return (json.dumps(thedata))

    def update(self, inobj):
        for a in inobj.keys():
            if hasattr(self, a):
                setattr(self, a, inobj[a])

    def __repr__(self):
        return "policyId='%s' userId='%s' imageDigest='%s' tag='%s'" % (
        self.policyId, self.userId, self.imageDigest, self.tag)


class Service(Base):
    __tablename__ = 'services'

    hostid = Column(String, primary_key=True)
    servicename = Column(String, primary_key=True)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    record_state_key = Column(String, default="active")
    record_state_val = Column(String)

    type = Column(String)
    version = Column(String)
    base_url = Column(String)
    short_description = Column(String)
    status = Column(Boolean)
    status_message = Column(String)
    heartbeat = Column(Integer)

    def make(self):
        ret = {}
        m = inspect(self)
        for c in m.attrs:
            ret[c.key] = None
        return (ret)

    def json(self):
        thedata = dict((key, value) for key, value in vars(self).iteritems() if not key.startswith('_'))
        return (json.dumps(thedata))

    def update(self, inobj):
        for a in inobj.keys():
            if hasattr(self, a):
                setattr(self, a, inobj[a])

    def __repr__(self):
        return "hostid='%s'" % (self.hostid)


class Registry(Base):
    __tablename__ = 'registries'

    registry = Column(String, primary_key=True)
    userId = Column(String, primary_key=True)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    record_state_key = Column(String, default="active")
    record_state_val = Column(String)
    registry_type = Column(String)

    registry_user = Column(String)
    registry_pass = Column(String)
    registry_verify = Column(Boolean)
    registry_meta = Column(String)

    def json(self):
        thedata = dict((key, value) for key, value in vars(self).iteritems() if not key.startswith('_'))
        return (json.dumps(thedata))

    def update(self, inobj):
        for a in inobj.keys():
            if hasattr(self, a):
                setattr(self, a, inobj[a])

    def __repr__(self):
        return "registry='%s' userId='%s' registry_user='%s'" % (self.registry, self.userId, self.registry_user)
