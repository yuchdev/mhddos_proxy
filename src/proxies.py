from random import choice
from typing import List, Optional

from PyRoxy import ProxyUtiles, ProxyType

from .core import logger, cl, PROXIES_URL
from .system import async_read_or_fetch, async_fetch


# @formatter:off
_globals_before = set(globals().keys()).union({'_globals_before'})
# noinspection PyUnresolvedReferences
from .load_proxies import *
decrypt_proxies = globals()[set(globals().keys()).difference(_globals_before).pop()]
# @formatter:on

class ProxySet:

    def __init__(self, proxies_file: Optional[str] = None):
        self._proxies_file = proxies_file
        self._loaded_proxies = []

    # XXX: we can optimize here a little bit by switching to lower-level interface
    #      with python_socks.async_.asyncio.Proxy object
    async def reload(self) -> List[str]:
        if self._proxies_file:
            proxies = await load_provided_proxies(self._proxies_file)
        else:
            proxies = await load_system_proxies()

        if proxies:
            self._loaded_proxies = list(proxies)
            return len(self._loaded_proxies)
        else:
            return 0

    def pick_random(self) -> str:
        return choice(self._loaded_proxies)
    
    def __len__(self) -> int:
        return len(self._loaded_proxies)


# XXX: support HTTP as well
# XXX: do we support auth?
def wrap_async(proxies):
    for proxy in proxies:
        if proxy.type == ProxyType.SOCKS4:
            yield Socks4Addr(proxy.host, proxy.port)
        elif proxy.type == ProxyType.SOCKS5:
            yield Socks5Addr(proxy.host, proxy.port)


# XXX: this function is no longer needed
def update_proxies(proxies_file, previous_proxies):
    if proxies_file:
        proxies = load_provided_proxies(proxies_file)
    else:
        proxies = load_system_proxies()

    if not proxies:
        if previous_proxies:
            proxies = previous_proxies
            logger.warning(f'{cl.MAGENTA}Буде використано попередній список проксі{cl.RESET}')
        else:
            logger.error(f'{cl.RED}Не знайдено робочих проксі - зупиняємо атаку{cl.RESET}')
            exit()

    return proxies


# XXX: move logging to the runner
async def load_provided_proxies(proxies_file: str) -> Optional[List[str]]:
    content = await async_read_or_fetch(proxies_file)
    if content is None:
        logger.warning(f'{cl.RED}Не вдалося зчитати проксі з {proxies_file}{cl.RESET}')
        return None

    # XXX: logging
    return content.split()

    proxies = ProxyUtiles.parseAll(content.split())
    if not proxies:
        logger.warning(f'{cl.RED}У {proxies_file} не знайдено проксі - перевірте формат{cl.RESET}')
    else:
        logger.info(f'{cl.YELLOW}Зчитано {cl.BLUE}{len(proxies)}{cl.YELLOW} проксі{cl.RESET}')
    return proxies


async def load_system_proxies():
    raw = await async_fetch(PROXIES_URL)
    # XXX: logging
    return decrypt_proxies(raw)
    try:
        proxies = ProxyUtiles.parseAll(decrypt_proxies(raw))
    except Exception:
        proxies = []
    if proxies:
        logger.info(f'{cl.YELLOW}Отримано персональну вибірку {cl.BLUE}{len(proxies):,}{cl.YELLOW} проксі зі списку {cl.BLUE}10.000+{cl.RESET}')
    else:
        logger.warning(f'{cl.RED}Не вдалося отримати персональну вибірку проксі{cl.RESET}')
    return proxies
