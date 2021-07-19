from anchore_engine import db
from anchore_engine.db import Task


def get_all(task_type=Task, session=None, json_safe=False):
    if not session:
        session = db.Session

    result = []

    for t in session.query(task_type):
        if json_safe:
            result.append(t.to_json())
        else:
            result.append(t.to_dict())

    return result
