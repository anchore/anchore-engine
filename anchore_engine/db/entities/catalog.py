"""
Entities for the catalog service including services, users, images, etc. Pretty much everything except image analysis data

"""
import datetime

from sqlalchemy import Column, Integer, String, Boolean, BigInteger, DateTime, LargeBinary, Index
from sqlalchemy import inspect

from .common import Base, anchore_now, anchore_uuid, UtilMixin, StringJSON, anchore_now_datetime


class Anchore(Base, UtilMixin):
    __tablename__ = 'anchore'

    service_version = Column(String, primary_key=True)
    db_version = Column(String, primary_key=True)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    record_state_key = Column(String, default="active")
    record_state_val = Column(String)

    scanner_version = Column(String)

    def __repr__(self):
        return "service_version='%s' db_version='%s' scanner_version='%s'" % (
        self.service_version, self.db_version, self.scanner_version)


class ArchiveMetadata(Base, UtilMixin):
    __tablename__ = 'archive_metadata'

    bucket = Column(String, primary_key=True)
    archiveId = Column(String, primary_key=True)
    userId = Column(String, primary_key=True)
    documentName = Column(String, primary_key=True)
    content_url = Column(String)
    is_compressed = Column(Boolean)
    digest = Column(String)
    size = Column(BigInteger)
    document_metadata = Column(String)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    record_state_key = Column(String, default="active")
    record_state_val = Column(String)


class ArchiveDocument(Base, UtilMixin):
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

    def __repr__(self):
        return "userId='%s'" % (self.userId)


class ObjectStorageRecord(Base, UtilMixin):
    """
    Content storage for the db driver for object storage.
    """
    __tablename__ = 'object_storage'

    userId = Column(String, primary_key=True)
    bucket = Column(String, primary_key=True)
    key = Column(String, primary_key=True)
    version = Column(String, primary_key=True, default='')
    object_metadata = Column(String)
    content = Column(LargeBinary)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)

# This will be migrated to the Account table
class User(Base, UtilMixin):
    """
    Legacy user definition. Migrated to Account + UserCredential

    """
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

    def __repr__(self):
        return "userId='%s'" % (self.userId)


class Event(Base, UtilMixin):
    __tablename__ = 'events'

    generated_uuid = Column(String, primary_key=True, default=anchore_uuid)
    created_at = Column(DateTime, default=anchore_now_datetime)
    resource_user_id = Column(String, nullable=True)
    resource_id = Column(String, nullable=True)
    resource_type = Column(String, nullable=True)
    source_servicename = Column(String, nullable=True)
    source_base_url = Column(String, nullable=True)
    source_hostid = Column(String, nullable=True)
    source_request_id = Column(String, nullable=True)
    type = Column(String)
    level = Column(String)
    message = Column(String)
    details = Column(StringJSON)
    timestamp = Column(DateTime)

    __table_args__ = (Index('ix_timestamp', timestamp.desc()),
                      Index('ix_resource_user_id', resource_user_id),
                      Index('ix_resource_type', resource_type),
                      Index('ix_resource_id', resource_id),
                      Index('ix_source_servicename', source_servicename),
                      Index('ix_source_hostid', source_hostid),
                      Index('ix_level', level))

    def __repr__(self):
        return "generated_uuid='%s' level='%s' message='%s'" % (self.generated_uuid, self.level, self.message)


class QueueItem(Base, UtilMixin):
    """
    Queue data used by notification system for queueing up notifications for delivery.

    """
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

    def __repr__(self):
        return "queueId='%s'" % (self.queueId)


class QueueMeta(Base, UtilMixin):
    """
    Metadata for queues themselves. msgs are stored in the queue table for simplequeue service.
    """
    __tablename__ = 'queuemeta'

    queueName = Column(String, primary_key=True)
    userId = Column(String, primary_key=True)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    record_state_key = Column(String, default="active")
    record_state_val = Column(String)
    qlen = Column(BigInteger, default=0)

    # For support of limiting number of messages being processed
    max_outstanding_messages = Column(Integer, default=0)

    # Default visibility timeout in seconds to be applied to messages if set
    visibility_timeout = Column(Integer, default=0)

    def __repr__(self):
        return "queueName='%s'" % (self.queueName)


class Queue(Base, UtilMixin):
    """
    Queue data used by the simplequeue service.
    """
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

    # Receipt handle is generated on dequeue and stored with the message as well as returned to the caller to support later deletion of the message
    receipt_handle = Column(String)
    visible_at = Column(DateTime)

    def __repr__(self):
        return "queueId='%s'" % (self.queueId)


class Subscription(Base, UtilMixin):
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

    def __repr__(self):
        return "userId='%s' subscription_type='%s' subscription_key='%s'" % (
        self.userId, self.subscription_type, self.subscription_key)

# if False:
#     class CatalogRepoTag(Base, UtilMixin):
#         __tablename__ = "catalog_repotag"
#
#         regrepo = Column(String, primary_key=True)
#         tag = Column(String, primary_key=True)
#         userId = Column(String, primary_key=True)
#         created_at = Column(Integer, default=anchore_now)
#         last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
#         record_state_key = Column(String, default="active")
#         record_state_val = Column(String)
#
#         image_type = Column(String)
#
#         def make(self):
#             ret = {}
#
#             m = inspect(self)
#             for c in m.attrs:
#                 ret[c.key] = None
#
#             return (ret)
#
#         def __repr__(self):
#             return "registry='%s'" % (self.registry)


class CatalogImage(Base, UtilMixin):
    __tablename__ = "catalog_image"

    imageDigest = Column(String, primary_key=True)
    userId = Column(String, primary_key=True)
    parentDigest = Column(String)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    analyzed_at = Column(Integer)
    record_state_key = Column(String, default="active")
    record_state_val = Column(String)

    image_type = Column(String)
    
    # image metadata
    arch = Column(String)
    distro = Column(String)
    distro_version = Column(String)
    dockerfile_mode = Column(String)
    image_size = Column(BigInteger)
    layer_count = Column(Integer)
    annotations = Column(String)

    analysis_status = Column(String)
    image_status = Column(String)

    def make(self):
        ret = {}

        m = inspect(self)
        for c in m.attrs:
            ret[c.key] = None

        return (ret)

    def __repr__(self):
        return "imageDigest='%s'" % (self.imageDigest)


class CatalogImageDocker(Base, UtilMixin):
    __tablename__ = "catalog_image_docker"

    imageDigest = Column(String, primary_key=True)
    userId = Column(String, primary_key=True)
    registry = Column(String, primary_key=True)
    repo = Column(String, primary_key=True)
    tag = Column(String, primary_key=True)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)
    tag_detected_at = Column(Integer, default=anchore_now)
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

    def __repr__(self):
        return "digest='%s'" % (self.digest)


class PolicyBundle(Base, UtilMixin):
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

    def __repr__(self):
        return "policyId='%s'" % (self.policyId)


class PolicyEval(Base, UtilMixin):
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
        selfdata = dict((key, value) for key, value in vars(self).items() if not key.startswith('_'))
        otherdata = dict((key, value) for key, value in vars(other).items() if not key.startswith('_'))
        for k in ['userId', 'imageDigest', 'tag', 'policyId', 'final_action']:
            try:
                if selfdata[k] != otherdata[k]:
                    return (False)
            except:
                return (False)
        return (True)

    def __repr__(self):
        return "policyId='%s' userId='%s' imageDigest='%s' tag='%s'" % (
        self.policyId, self.userId, self.imageDigest, self.tag)


class Service(Base, UtilMixin):
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

    def __repr__(self):
        return "hostid='%s'" % (self.hostid)


class Registry(Base, UtilMixin):
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

    def __repr__(self):
        return "registry='%s' userId='%s' registry_user='%s'" % (self.registry, self.userId, self.registry_user)


# Application-defined lease using a flag in a db row. These are leases, not locks, because they have expirations.
class Lease(Base, UtilMixin):
    __tablename__ = 'leases'

    _default_expiration_duration = 10

    id = Column(String, primary_key=True)
    held_by = Column(String)
    expires_at = Column(DateTime)
    epoch = Column(BigInteger, default=0)

    # Some convenience functions, these should be executed inside for_update locks
    def do_acquire(self, holder_id, duration_sec=None):
        return self.is_available() and self.set_holder(holder_id, duration_sec=duration_sec)

    def is_available(self):
        return self.held_by is None or self.is_expired()

    def is_expired(self):
        return self.expires_at is None or self.expires_at < datetime.datetime.utcnow()

    def set_holder(self, id, duration_sec=None):
        if not duration_sec:
            duration_sec = self._default_expiration_duration

        self.held_by = id
        self.expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=duration_sec)
        self.epoch += 1
        return True

    def release_holder(self):
        self.expires_at = None
        self.held_by = None
        self.epoch += 1
        return True

    def __str__(self):
        return '<{} id={},held_by={},expires_at={},epoch={}>'.format(self.__class__.__name__, self.id, self.held_by, self.expires_at.isoformat() if self.expires_at else self.expires_at, self.epoch)


