"""
Entities for task management.
"""

import datetime

from sqlalchemy import Boolean, Column, DateTime, Enum, ForeignKey, Integer, String

from anchore_engine.db.entities.common import Base, UtilMixin


class Task(Base, UtilMixin):
    """
    A generic task record for system tasks
    """

    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    state = Column(
        Enum(
            "initializing",
            "pending",
            "running",
            "complete",
            "failed",
            name="task_states",
        ),
        default="initializing",
    )
    last_state = Column(
        Enum(
            "initializing",
            "pending",
            "running",
            "complete",
            "failed",
            name="task_states",
        )
    )
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    started_at = Column(DateTime)
    ended_at = Column(DateTime)
    last_updated = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )
    executor_id = Column(String)
    type = Column(String)

    __mapper_args__ = {"polymorphic_identity": "task", "polymorphic_on": type}


class ArchiveMigrationTask(Task):
    __tablename__ = "archive_migration_tasks"

    id = Column(Integer, ForeignKey("tasks.id"), primary_key=True)
    migrate_from_driver = Column(String)
    migrate_to_driver = Column(String)
    archive_documents_to_migrate = Column(Integer)
    archive_documents_migrated = Column(Integer)
    online_migration = Column(Boolean)

    __mapper_args__ = {"polymorphic_identity": "archivemigrationtask"}


# TODO: finish this, scheduled tasks instead of queues make things *much* easier in many cases (e.g. internal monitors)
#
# class AnalysisArchiveTransitionTask(Task):
#     __tablename__ = 'analysis_archive_transition_tasks'
#
#     id = Column(Integer, ForeignKey('tasks.id'), primary_key=True)
#     account = Column(String)
#     transition_rules = Column(JSON)
#
#
# class TaskSchedule(object):
#     __tablename__ = 'task_schedules'
#
#     schedule_id = Column(Integer, primary_key=True, autoincrement=True)
#     task_type = Column(String)
#     interval_count = Column(Integer) # Number of intervals of the specified unit between task executions
#     interval_unit = Column(Enum['seconds', 'minutes', 'hours', 'days'])
#
#     last_execution_at = Column(DateTime)
#     last_task_id = Column(Integer)
#
#     next_execution_at = Column(DateTime)
#     task_in_progress = Column(Integer)
#
#     created_at = Column(DateTime)
#     last_updated = Column(DateTime)
