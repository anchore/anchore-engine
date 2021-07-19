"""
Async tasks that the worker component uses
"""
import datetime
import enum
import threading
from abc import abstractmethod
from uuid import uuid4


class Status(enum.Enum):
    pending = "pending"
    running = "running"
    failed = "failed"
    success = "success"
    complete = "complete"


class WorkerTask(threading.Thread):
    def __init__(self):
        super().__init__()
        self.task_id = uuid4().hex
        self.created_at = datetime.datetime.utcnow()
        self.started_at = None
        self.finished_at = None
        self.status = Status.pending

    def _success(self):
        self.status = Status.success
        self.finished_at = datetime.datetime.utcnow()

    def _failed(self):
        self.status = Status.failed
        self.finished_at = datetime.datetime.utcnow()

    def _start(self):
        self.status = Status.running
        self.started_at = datetime.datetime.utcnow()

    def _pre_exec(self):
        self._start()

    @abstractmethod
    def execute(self):
        pass

    def _post_exec(self, exception: Exception = None):
        if exception is None:
            self._success()
        else:
            self._failed()

    def run(self):
        self._pre_exec()
        try:
            self.execute()
            self._post_exec()
        except Exception as ex:
            self._post_exec(ex)
