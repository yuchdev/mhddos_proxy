from hashlib import md5
import time
from typing import Dict, Tuple
from zlib import crc32


class GOSSolver:

    _path = bytes.fromhex("68747470733a2f2f7777772e676f7375736c7567692e72752f5f5f6a7363682f736368656d612e6a736f6e").decode()
    _verifier = bytes.fromhex("5f5f6a7363682f7374617469632f7363726970742e6a73")
    
    @property
    def path(self) -> str:
        return self._path

    def _challenge(self, value: str) -> str:
        return md5(value.encode()).digest().hex()

    def verify(self, resp: bytes) -> bool:
        return self._verifier not in resp
    
    def solve(self, ua, resp) -> Tuple[int, Dict[str, str]]:
        a, ip, cn = resp["a"], resp["ip"], resp["cn"]
        ts = int(time.time())
        bucket = ts - ts%a
        value = f"{ua}:{ip}:{bucket}"
        for pos in range(10_000_000):
            response = self._challenge(f"{value}{pos}")
            if response[6:10] == "3fe3":
                return (bucket+a, {
                    cn: response.upper(),
                    f"{cn}_2": pos,
                    f"{cn}_3": crc32(value.encode())
                })
        raise ValueError("invalid input")
