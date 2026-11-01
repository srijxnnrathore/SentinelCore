import asyncio
from dataclasses import dataclass
from typing import Optional
from src.core.audit import log_security_event
from src.core.threat_detector import threat_detector

@dataclass
class SecurityEvent:
    tenant_id: str
    actor_id: str
    action: str
    status: str
    resource_id: Optional[str]
    ip_address: Optional[str]
    record_threat: bool = False

class SecurityEventQueue:
    def __init__(self, maxsize: int = 10000):
        self.queue: asyncio.Queue[SecurityEvent] = asyncio.Queue(maxsize=maxsize)
        self._worker_task: Optional[asyncio.Task] = None

    def push(self, event: SecurityEvent) -> None:
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            pass  # Drop oldest or log to stderr to prevent backpressure DoS

    async def start(self) -> None:
        self._worker_task = asyncio.create_task(self._drain_loop())

    async def stop(self) -> None:
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass

    async def _drain_loop(self) -> None:
        while True:
            event = await self.queue.get()
            try:
                if event.record_threat:
                    await threat_detector.record_violation(event.tenant_id)
                await log_security_event(
                    actor_id=event.actor_id,
                    action=event.action,
                    status=event.status,
                    resource_id=event.resource_id,
                    ip_address=event.ip_address,
                    tenant_id=event.tenant_id,
                )
            except Exception:
                pass
            finally:
                self.queue.task_done()

security_event_queue = SecurityEventQueue()