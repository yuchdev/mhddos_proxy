import asyncio
from concurrent.futures import Future, Executor
from concurrent.futures.thread import _WorkItem
from functools import wraps
import queue
from threading import Thread
from typing import Any, Optional

from src.core import logger, cl


TERMINATE = object()


async def safe_run(f) -> Optional[Any]:
    try:
        return await f()
    except asyncio.CancelledError:
        raise
    except Exception as e:
        # XXX: there should be an option to see error
        #      e.g. TRACE level of logging or something
        return None


def scale_attack(factor: int):
    """Runs a given task multiple times"""
    assert factor > 0
    def _wrapper(f):
        @wraps(f)
        async def _inner(*args, **kwargs):
            tasks = [asyncio.create_task(f(*args, **kwargs)) for _ in range(factor)]
            done, _ = await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)
            for fut in done:
                try:
                    if fut.result():
                        return fut.result()
                except asyncio.CancelledError as e:
                    raise e
                except:
                    pass
            return False
        return _inner
    return _wrapper


class DaemonThreadPool(Executor):

    def __init__(self, num_workers: int = 32):
        self._queue = queue.SimpleQueue()
        self._num_workers = num_workers

    def start_all(self):
        for _ in range(self._num_workers):
            try:
                Thread(target=self._worker, daemon=True).start()
            except RuntimeError:
                logger.error(f'{cl.RED}Не вдалося запустити атаку - вичерпано ліміт потоків системи{cl.RESET}')
                exit()
        return self

    def terminate_all(self):
        for _ in range(self._num_workers):
            self._queue.put(TERMINATE)

    def submit(self, fn, *args, **kwargs):
        f = Future()
        w = _WorkItem(f, fn, args, kwargs)
        self._queue.put(w)
        return f

    def _worker(self):
        while True:
            work_item = self._queue.get(block=True)
            if work_item is TERMINATE:
                return

            if work_item is not None:
                work_item.run()
                del work_item
