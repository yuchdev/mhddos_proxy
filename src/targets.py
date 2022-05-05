from hashlib import md5
import time
from typing import Dict, List, Optional, Tuple

from dns import inet
from yarl import URL

from .core import logger, cl
from .dns_utils import resolve_all_targets
from .system import read_or_fetch


Options = Dict[str, str]


class Target:
    OPTION_RPC = "rpc"
    OPTION_TRANSPORT = "transport"
    OPTION_HIGH_WATERMARK = "watermark"

    url: URL
    method: Optional[str]
    options: Options
    addr: Optional[str]

    def __init__(
        self,
        url: URL,
        method: Optional[str] = None,
        options: Optional[Options] = None,
        addr: Optional[str] = None
    ):
        self.url = url
        self.method = method
        self.options = options or {}
        self.addr = addr

    @classmethod
    def from_string(cls, raw: str) -> "Target":
        parts = [part.strip() for part in raw.split(" ")]
        n_parts = len(parts)
        url = URL(Target.prepare_url(parts[0]))
        method = parts[1].upper() if n_parts > 1 else None
        options = dict(tuple(part.split("=")) for part in parts[2:])
        addr = url.host if inet.is_address(url.host) else None
        return cls(url, method, options, addr)

    @staticmethod
    def prepare_url(target: str) -> str:
        if '://' in target:
            return target

        try:
            _, port = target.split(':', 1)
        except ValueError:
            port = '80'

        scheme = 'https://' if port == '443' else 'http://'
        return scheme + target

    @property
    def is_resolved(self) -> bool:
        return self.addr is not None

    @property
    def is_udp(self) -> bool:
        return self.url.scheme == "udp"

    def option(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self.options.get(key, default)

    def has_option(self, key: str) -> bool:
        return key in self.options

    @property
    def has_options(self) -> bool:
        return len(self.options) > 0

    @property
    def options_repr(self) -> Optional[str]:
        if not self.has_options: return None
        return " ".join(f"{k}={v}" for k, v in self.options.items())

    def human_repr(self) -> str:
        if self.url.host != self.addr:
            return f"{self.url.host} ({self.addr})"
        else:
            return self.url.host

    def __hash__(self):
        return hash(self.url)


class TargetsLoader:

    def __init__(self, targets, config):
        self._targets = [Target.from_string(t) for t in targets]
        self._config = config
        self._tag: Optional[str] = None
        self._last_loaded_at: Optional[float] = None
        self._cached_targets = None

    @property
    def dynamic(self):
        return self._config is not None

    @property
    def age(self) -> Optional[float]:
        if not self._config: return None
        if not self._last_loaded_at: return 0
        return time.time() - self._last_loaded_at

    async def load(self, resolve: bool = False) -> Tuple[List[Target], bool]:
        config_targets = await self._load_config()
        if config_targets:
            logger.info(
                f"{cl.YELLOW}Завантажено конфіг {self._config} "
                f"на {cl.BLUE}{len(config_targets)} цілей{cl.RESET}")
        all_targets = self._targets + (config_targets or [])
        if resolve:
            all_targets = await resolve_all_targets(all_targets)
            all_targets = [target for target in all_targets if target.is_resolved]
        changed = (all_targets == self._cached_targets)
        self._cached_targets = all_targets
        self._last_loaded_at = time.time()
        return all_targets, changed

    # XXX: fix this to work properly with ETag
    async def _load_config(self) -> List[Target]:
        if not self._config:
            return []

        config_content = await read_or_fetch(self._config)
        if config_content is None:
            raise RuntimeError("Failed to load configuration")

        self._tag = md5(config_content.encode()).hexdigest()

        targets = []
        for row in config_content.splitlines():
            target = row.strip()
            if target and not target.startswith('#'):
                targets.append(Target.from_string(target))

        return targets

