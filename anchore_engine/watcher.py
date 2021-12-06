from dataclasses import dataclass, asdict
from typing import List, Any, Dict
from abc import ABC, abstractmethod

@dataclass
class WatcherConfig:
    watcher_key: str
    task_lease_id: str
    task_type: str
    cycle_timer: int
    min_cycle_timer: int
    max_cycle_timer: int
    args: List[Any]
    initialized: bool = False
    last_queued: int = 0
    last_return: bool = False

class BaseWatcher(ABC):
    config: WatcherConfig

    @abstractmethod
    def handle(self, *args, **kwargs):
        ...

    def to_watcher_dict(self) -> Dict[str, Any]:
        watcher_dict = asdict(self.config)
        watcher_dict["taskType"] = watcher_dict["task_type"]
        del watcher_dict["task_type"]
        watcher_dict["handler"] = self.handle
        return watcher_dict
