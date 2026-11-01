import asyncio
import logging
from dataclasses import dataclass
from typing import Optional
from src.core.audit import log_security_event
from src.core.threat_detector import threat_detector

logger = logging.getLogger("sentinelcore.event_queue")

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
        self.maxsize = maxsize
        self._queue: Optional[asyncio.Queue[SecurityEvent]] = None
        self._worker_task: Optional[asyncio.Task] = None
        self._accepting: bool = True
        self._dropped_events_counter: int = 0

    @property
    def queue(self) -> asyncio.Queue[SecurityEvent]:
        loop = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        if self._queue is None or (loop and getattr(self._queue, "_loop", None) not in (None, loop)):
            self._queue = asyncio.Queue(maxsize=self.maxsize)
        return self._queue

    @property
    def dropped_events_counter(self) -> int:
        return self._dropped_events_counter

    def push(self, event: SecurityEvent) -> None:
        if not self._accepting:
            self._dropped_events_counter += 1
            logger.error(
                "Dropped security event: event queue is shutting down",
                extra={
                    "action": event.action,
                    "tenant_id": event.tenant_id,
                    "dropped_events_counter": self._dropped_events_counter,
                },
            )
            return

        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            self._dropped_events_counter += 1
            logger.error(
                "Dropped security event due to QueueFull",
                extra={
                    "action": event.action,
                    "tenant_id": event.tenant_id,
                    "dropped_events_counter": self._dropped_events_counter,
                },
            )
            return

        # Ensure background drain loop is active if an event loop is running
        if self._worker_task is None or self._worker_task.done():
            try:
                loop = asyncio.get_running_loop()
                if loop.is_running():
                    self._worker_task = loop.create_task(self._drain_loop())
            except RuntimeError:
                pass

    async def start(self) -> None:
        self._accepting = True
        loop = asyncio.get_running_loop()
        if self._queue is None or getattr(self._queue, "_loop", None) not in (None, loop):
            self._queue = asyncio.Queue(maxsize=self.maxsize)
        if self._worker_task is None or self._worker_task.done():
            self._worker_task = loop.create_task(self._drain_loop())

    async def stop(self, drain_timeout: float = 5.0) -> None:
        self._accepting = False
        if self._worker_task and not self._worker_task.done():
            try:
                await asyncio.wait_for(self.queue.join(), timeout=drain_timeout)
            except asyncio.TimeoutError:
                logger.warning(
                    "Security event queue drain timed out after %.2f seconds; %d items remaining",
                    drain_timeout,
                    self.queue.qsize(),
                    extra={
                        "drain_timeout": drain_timeout,
                        "remaining_items": self.queue.qsize(),
                    },
                )
            finally:
                self._worker_task.cancel()
                try:
                    await self._worker_task
                except asyncio.CancelledError:
                    pass
                self._worker_task = None
        self._queue = None
        self._accepting = True

    def reset(self) -> None:
        if self._worker_task and not self._worker_task.done():
            self._worker_task.cancel()
        self._worker_task = None
        self._queue = None
        self._accepting = True

    async def _drain_loop(self) -> None:
        while True:
            try:
                event = await self.queue.get()
            except asyncio.CancelledError:
                break

            try:
                max_attempts = 3
                threat_recorded = False
                for attempt in range(max_attempts):
                    try:
                        if event.record_threat and not threat_recorded:
                            await threat_detector.record_violation(event.tenant_id)
                            threat_recorded = True

                        await log_security_event(
                            actor_id=event.actor_id,
                            action=event.action,
                            status=event.status,
                            resource_id=event.resource_id,
                            ip_address=event.ip_address,
                            tenant_id=event.tenant_id,
                        )
                        break
                    except Exception as exc:
                        if attempt < max_attempts - 1:
                            backoff = 0.1 * (2 ** attempt)
                            logger.warning(
                                "Failed to process security event (attempt %d/%d): %s. Retrying in %.2fs",
                                attempt + 1,
                                max_attempts,
                                exc,
                                backoff,
                                extra={
                                    "action": event.action,
                                    "tenant_id": event.tenant_id,
                                    "attempt": attempt + 1,
                                    "max_attempts": max_attempts,
                                    "error": str(exc),
                                },
                            )
                            await asyncio.sleep(backoff)
                        else:
                            logger.error(
                                "Exhausted retries processing security event after %d attempts: %s",
                                max_attempts,
                                exc,
                                extra={
                                    "action": event.action,
                                    "tenant_id": event.tenant_id,
                                    "attempt": attempt + 1,
                                    "max_attempts": max_attempts,
                                    "error": str(exc),
                                },
                                exc_info=True,
                            )
            except asyncio.CancelledError:
                raise
            finally:
                self.queue.task_done()

security_event_queue = SecurityEventQueue()
