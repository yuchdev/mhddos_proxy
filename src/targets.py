import base64
import time
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from dns import inet
from yarl import URL

from .core import cl, logger
from .dns_utils import resolve_all_targets
from .i18n import translate as t
from .system import read_or_fetch


Options = Dict[str, str]


class Target:
    OPTION_IP = "ip"
    OPTION_RPC = "rpc"
    OPTION_HIGH_WATERMARK = "watermark"

    __slots__ = ['url', 'method', 'options', 'addr', 'hash']

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
        self.addr = self.option(Target.OPTION_IP, addr)

        self.hash = hash((self.url, self.method, tuple(self.options.items()), self.addr))

    def __eq__(self, other):
        return self.hash == other.hash

    def __hash__(self):
        return self.hash

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
        if not self.has_options:
            return None
        return " ".join(f"{k}={v}" for k, v in self.options.items())

    def human_repr(self) -> str:
        if self.url.host != self.addr:
            return f"{self.url.host} ({self.addr})"
        else:
            return self.url.host

    def create_stats(self, method: str) -> "TargetStats":
        return TargetStats(self, method)


ENC_KEYS = {
    b'\xe4\xdc\xf7\x1f': b'fZPK2OTLiNdqVDBxJTSMuph/rfLzpFWHDmHC1/+rR1s=',
}


class TargetsLoader:
    def __init__(self, targets, targets_config, global_config, it_army: bool = False):
        self._targets = [Target.from_string(raw) for raw in targets]
        self._cmd_targets_config = targets_config
        self._global_config = global_config
        self._it_army = it_army
        self._cached_targets = []

    async def reload(self) -> Tuple[List[Target], bool]:
        config_targets = await self._load_config()
        if config_targets:
            logger.info(
                f"{cl.YELLOW}{t('Loaded config for')} {cl.BLUE}{len(config_targets)} {t('targets')}{cl.RESET}"
            )

        all_targets = await resolve_all_targets(self._targets + config_targets)
        all_targets = [target for target in all_targets if target.is_resolved]

        is_changed = (set(all_targets) != set(self._cached_targets))
        self._cached_targets = all_targets
        return all_targets, is_changed

    async def _load_config(self):
        if self._it_army:
            target_urls = self._global_config['it_army_config_urls_list']
        elif self._cmd_targets_config:
            target_urls = self._cmd_targets_config  # do not make a list, so local path can be handled by read_or_fetch
        else:
            return []

        content = await read_or_fetch(target_urls)
        if content is None:
            raise RuntimeError('Failed to load configuration')

        content = self._possibly_decrypt(content).decode()

        targets = []
        for row in content.splitlines():
            target = row.strip()
            if target and not target.startswith('#'):
                try:
                    targets.append(Target.from_string(target))
                except Exception:
                    logger.warning(f'{cl.MAGENTA}Failed to parse: {target}{cl.RESET}')

        return targets

    def _possibly_decrypt(self, content):
        nonce_len = 12
        for version, key in ENC_KEYS.items():
            if content.startswith(version):
                v_len = len(version)
                cip = ChaCha20Poly1305(key=base64.b64decode(key))
                nonce = content[v_len: v_len + nonce_len]
                return cip.decrypt(nonce, content[v_len + nonce_len:], None)
        return content


class TargetStats:
    __slots__ = ['_target', '_method', '_sig', '_requests', '_bytes', '_conns', '_reset_at']

    def __init__(self, target: Target, method: str):
        self._target = target
        self._method = method
        self._sig = target.options_repr
        self._requests: int = 0
        self._bytes: int = 0
        self._conns: int = 0
        self._reset_at = time.perf_counter()

    @property
    def target(self) -> Tuple[Target, str, str]:
        return self._target, self._method, self._sig

    def track(self, rs: int, bs: int) -> None:
        self._requests += rs
        self._bytes += bs

    def track_open_connection(self) -> None:
        self._conns += 1

    def track_close_connection(self) -> None:
        if self._conns <= 0:
            logger.debug(
                f"Invalid connection stats calculation for {self._target.human_repr()}")
        else:
            self._conns -= 1

    def reset(self) -> Tuple[int, int, int]:
        sent_requests, sent_bytes, prev_reset_at = self._requests, self._bytes, self._reset_at
        self._requests, self._bytes, self._reset_at = 0, 0, time.perf_counter()
        interval = self._reset_at - prev_reset_at
        return int(sent_requests / interval), int(8 * sent_bytes / interval), self._conns
