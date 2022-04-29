from asyncio import gather
from asyncstdlib.functools import lru_cache
from typing import Dict, List, Optional

from dns.asyncresolver import Resolver
import dns.exception
from yarl import URL

from .core import logger, cl
from .targets import Target


resolver = Resolver(configure=False)
resolver.nameservers = ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '208.67.222.222', '208.67.220.220']


@lru_cache(maxsize=1024)
async def resolve_host(host: str) -> str:  # TODO: handle multiple IPs?
    if dns.inet.is_address(host):
        return host
    answer = await resolver.resolve(host)
    return answer[0].to_text()


async def resolve_url(url: str) -> str:
    return await resolve_host(URL(url).host)


async def safe_resolve_host(host: str) -> Optional[str]:
    try:
        return await resolve_host(host)
    except dns.exception.DNSException:
        logger.warning(f'{cl.YELLOW}Ціль {cl.BLUE}{host}{cl.YELLOW} не доступна і {cl.RED}не буде атакована{cl.RESET}')
        return None


async def resolve_all(hosts: List[str]) -> Dict[str, str]:
    unresolved_hosts = list(set(host for host in hosts if not dns.inet.is_address(host)))
    answers = await gather(*[safe_resolve_host(h) for h in unresolved_hosts])
    ips = dict(zip(unresolved_hosts, answers))
    return {host:ips.get(host, host) for host in hosts}


async def resolve_all_targets(targets: List[Target]) -> List[Target]:
    unresolved_hosts = list(set(target.url.host for target in targets if not target.is_resolved))
    ips = await resolve_all(unresolved_hosts)
    for target in targets:
        if not target.is_resolved:
            target.addr = ips.get(target.url.host)
    return targets
