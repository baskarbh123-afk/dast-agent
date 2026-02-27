import asyncio
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class TaskPriority(Enum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class Task:
    name: str
    handler: str  # scanner module name or action
    target: str  # URL or resource
    priority: TaskPriority = TaskPriority.MEDIUM
    status: TaskStatus = TaskStatus.PENDING
    params: dict = field(default_factory=dict)
    result: dict | None = None
    error: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str | None = None
    retries: int = 0
    max_retries: int = 3

    def __lt__(self, other):
        return self.priority.value > other.priority.value  # Higher priority first


class TaskQueue:
    def __init__(self):
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._all_tasks: list[Task] = []
        self._completed: list[Task] = []
        self._failed: list[Task] = []
        self._lock = asyncio.Lock()

    async def add(self, task: Task):
        async with self._lock:
            self._all_tasks.append(task)
            await self._queue.put((task.priority.value * -1, id(task), task))

    async def get(self) -> Task | None:
        try:
            _, _, task = await asyncio.wait_for(self._queue.get(), timeout=5)
            task.status = TaskStatus.RUNNING
            return task
        except asyncio.TimeoutError:
            return None

    async def complete(self, task: Task, result: dict | None = None):
        async with self._lock:
            task.status = TaskStatus.COMPLETED
            task.result = result
            task.completed_at = datetime.now(timezone.utc).isoformat()
            self._completed.append(task)

    async def fail(self, task: Task, error: str):
        async with self._lock:
            task.retries += 1
            if task.retries < task.max_retries:
                task.status = TaskStatus.PENDING
                task.error = error
                await self._queue.put((task.priority.value * -1, id(task), task))
            else:
                task.status = TaskStatus.FAILED
                task.error = error
                self._failed.append(task)

    def done(self):
        self._queue.task_done()

    @property
    def pending_count(self) -> int:
        return self._queue.qsize()

    @property
    def completed_count(self) -> int:
        return len(self._completed)

    @property
    def failed_count(self) -> int:
        return len(self._failed)

    @property
    def total_count(self) -> int:
        return len(self._all_tasks)

    def get_stats(self) -> dict:
        return {
            "total": self.total_count,
            "pending": self.pending_count,
            "completed": self.completed_count,
            "failed": self.failed_count,
        }
