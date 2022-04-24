from contextlib import suppress
import os.path
import time
from typing import Optional

from aiohttp import ClientSession

from src.core import VERSION_URL


def fix_ulimits():
    try:
        import resource
    except ImportError:
        return

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < hard:
        with suppress(Exception):
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))


async def read_or_fetch(path_or_url: str) -> Optional[str]:
    if os.path.exists(path_or_url):
        with open(path_or_url, 'r') as f:
            return f.read()
    return await fetch(path_or_url)


# XXX: errors and retries
async def fetch(url: str) -> Optional[str]:
    async with ClientSession(raise_for_status=True) as session:
        async with session.get(url, timeout=10) as response:
           return await response.text() 


async def is_latest_version():
    latest = int((await read_or_fetch(VERSION_URL)).strip())
    current = int((await read_or_fetch('version.txt')).strip())
    return current >= latest
