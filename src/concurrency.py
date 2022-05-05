import asyncio
from functools import wraps
from typing import Any, Optional


async def safe_run(f) -> Optional[Any]:
    try:
        return await f()
    except asyncio.CancelledError as e:
        raise e
    except asyncio.TimeoutError:
        return None
    except Exception:
        # XXX: there should be an option to see error
        #      e.g. TRACE level of logging or something
        return None


def scale_attack(factor: int):
    """Runs a given task multiple times"""
    assert factor > 0

    def _wrapper(f):
        @wraps(f)
        async def _inner(*args, **kwargs) -> bool:
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
