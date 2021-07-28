from collections import namedtuple
import datetime
import enum
import json

from anchore_engine.subsys.servicestatus import get_my_service_record

CategoryDescriptor = namedtuple(
    "CategoryDescriptor", field_names=["name", "description"]
)


class EventMeta(type):
    """
    Metaclass to create a registry for all types that use this as meta.
    Must have callable 'fq_event_type' class attribute and '__event_type__' class attribute

    """

    def __init__(cls, name, bases, dct):
        if not hasattr(cls, "registry"):
            cls.registry = []
        else:
            if "__event_type__" in dct and dct["__event_type__"]:
                cls.registry.append(cls)

        super(EventMeta, cls).__init__(name, bases, dct)

    def registered_event_types(cls):
        return [x.fq_event_type() for x in cls.registry]

    def registered_events(cls):
        return cls.registry

    def registered_categories(cls):
        return list(
            set([x.__category__ for x in cls.registry if hasattr(x, "__category__")])
        )

    def registered_subcategories(cls):
        return list(
            set(
                [
                    x.__subcategory__
                    for x in cls.registry
                    if hasattr(x, "__subcategory__")
                ]
            )
        )


class EventLevel(enum.Enum):
    INFO = "info"
    ERROR = "error"


class EventBase(object, metaclass=EventMeta):
    """
    Each subclass should have:
    __category__ set to None or a CategoryDescriptor obj
    __subcategory__ set to None or a CategoryDescriptor obj
    __event_type__ set to a string value, empty string is considered unset

    """

    __category__ = None
    __subcategory__ = None
    __event_type__ = ""
    __resource_type__ = None
    __level__ = EventLevel.INFO
    __message__ = None

    def __init__(self, user_id, details, request_id=None, resource_id=None):
        self.user_id = user_id
        self.details = (
            details
            if isinstance(details, dict)
            else ({"msg": str(details)} if details is not None else {})
        )
        self.timestamp = datetime.datetime.utcnow().isoformat()
        self.request_id = request_id
        self.resource_id = resource_id
        self.service_record = get_my_service_record()

    @classmethod
    def fq_event_type(cls):
        return "{}.{}.{}".format(
            cls.__category__.name if cls.__category__ else "",
            cls.__subcategory__.name if cls.__subcategory__ else "",
            cls.__event_type__,
        ).lower()

    def to_json(self):
        return json.dumps(self.to_dict())

    def to_dict(self):
        event_dict = dict()
        event_dict["type"] = self.fq_event_type()
        event_dict["level"] = self.level
        event_dict["message"] = self.__message__
        event_dict["details"] = self.details
        event_dict["timestamp"] = self.timestamp
        event_dict["resource"] = {
            "user_id": self.user_id,
            "type": self.__resource_type__,
            "id": self.resource_id,
        }
        event_dict["source"] = {"request_id": self.request_id}
        if self.service_record:
            event_dict["source"]["servicename"] = self.service_record.get(
                "servicename", None
            )
            event_dict["source"]["hostid"] = self.service_record.get("hostid", None)
            event_dict["source"]["base_url"] = self.service_record.get("base_url", None)

        return event_dict

    def describe(self):
        return "event: {}, resource: {}".format(self.__event_type__, self.resource_id)

    @property
    def level(self):
        return self.__level__.value
