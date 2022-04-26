from hashlib import md5
import time
from typing import Dict, List, Optional, Tuple

from dns import inet
from yarl import URL

from .core import logger, cl
from .system import read_or_fetch


Options = Dict[str, str]


class Target:
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

    def __hash__(self):
        return hash(self.url)


class TargetsLoader:

    def __init__(self, targets, config):
        self._targets = [Target.from_string(t) for t in targets]
        self._config = config
        self._tag: Optional[str] = None
        self._last_loaded_at: Optional[float] = None

    @property
    def dynamic(self):
        return self._config is not None

    @property
    def age(self) -> Optional[float]:
        if self._last_loaded_at is None: return None
        return time.time() - self._last_loaded_at

    async def load(self) -> Tuple[List[Target], bool]:
        config_targets, changed = await self._load_config()
        self._last_loaded_at = time.time()
        if config_targets:
            logger.info(
                f"{cl.YELLOW}Завантажено конфіг {self._config} "
                f"на {cl.BLUE}{len(config_targets)} цілей{cl.RESET}")
        return self._targets + (config_targets or []), changed

    async def _load_config(self) -> Tuple[List[Target], bool]:
        if not self._config:
            return [], False

        config_content = await read_or_fetch(self._config)
        if config_content is None:
            raise RuntimeError("Failed to load configuration")

        etag = md5(config_content.encode()).hexdigest()
        changed = self._tag is None or self._tag != etag
        self._tag = etag

        targets = []
        for row in config_content.splitlines():
            target = row.strip()
            if target and not target.startswith('#'):
                targets.append(Target.from_string(target))

        return targets, changed

