from typing import List, Dict, Optional
from pydantic import BaseModel
from enum import Enum
import uuid
from datetime import datetime

class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class Task(BaseModel):
    id: str = str(uuid.uuid4())
    description: str
    tool: str
    parameters: Dict
    status: TaskStatus = TaskStatus.PENDING
    retries: int = 0
    max_retries: int = 3
    created_at: datetime = datetime.now()
    updated_at: datetime = datetime.now()
    result: Optional[Dict] = None

class TaskManager:
    def __init__(self):
        self.tasks: List[Task] = []

    def add_task(self, description: str, tool: str, parameters: Dict) -> Task:
        task = Task(
            description=description,
            tool=tool,
            parameters=parameters
        )
        self.tasks.append(task)
        return task

    def update_task_status(self, task_id: str, status: TaskStatus, result: Optional[Dict] = None):
        for task in self.tasks:
            if task.id == task_id:
                task.status = status
                task.updated_at = datetime.now()
                if result:
                    task.result = result
                break

    def get_next_task(self) -> Optional[Task]:
        pending_tasks = [t for t in self.tasks if t.status == TaskStatus.PENDING]
        return pending_tasks[0] if pending_tasks else None