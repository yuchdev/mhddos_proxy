from contextlib import suppress
import os.path
import time
from typing import Optional

from aiohttp import ClientSession
import requests

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


def read_or_fetch(path_or_url):
    if os.path.exists(path_or_url):
        with open(path_or_url, 'r') as f:
            return f.read()
    return fetch(path_or_url)


async def async_read_or_fetch(path_or_url: str) -> Optional[str]:
    if os.path.exists(path_or_url):
        with open(path_or_url, 'r') as f:
            return f.read()
    return await async_fetch(path_or_url)


def fetch(url):
    attempts = 4
    for attempt in range(attempts):
        try:
            response = requests.get(url, timeout=10)
            # XXX: should we raise for status here?
            return response.text
        except requests.RequestException:
            if attempt != attempts - 1:
                time.sleep(attempt + 1)
    return None

# XXX: errors and retries
async def async_fetch(url: str) -> Optional[str]:
    async with ClientSession() as session:
        async with session.get(url, timeout=10) as response:
           return await response.text() 


def is_latest_version():
    latest = int(read_or_fetch(VERSION_URL).strip())
    current = int(read_or_fetch('version.txt').strip())
    return current >= latest
