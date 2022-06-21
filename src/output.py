from typing import List, Optional

from .core import CPU_COUNT, DEFAULT_THREADS, cl, logger, USE_ONLY_MY_IP
from .i18n import translate as t
from .mhddos import Tools
from .system import NetStats
from .targets import TargetStats


def show_statistic(statistics: List[TargetStats], net_stats: Optional[NetStats], debug: bool):
    pps_name, total_pps, total_bps, total_in_flight = "Requests", 0, 0, 0
    for stats in statistics:
        pps, bps, in_flight_conn = stats.reset()
        total_pps += pps
        total_bps += bps
        total_in_flight += in_flight_conn

        if debug:
            (target, method, sig) = stats.target
            method_sig = f" ({sig})" if sig is not None else ""
            logger.info(
                f"{cl.YELLOW}{t('Target')}:{cl.BLUE} {target.human_repr()}, "
                f"{cl.YELLOW}{t('Port')}:{cl.BLUE} {target.url.port}, "
                f"{cl.YELLOW}{t('Method')}:{cl.BLUE} {method}{method_sig}, "
                f"{cl.YELLOW}{t('Connections')}:{cl.BLUE} {Tools.humanformat(in_flight_conn)}, "
                f"{cl.YELLOW}{t('Requests')}:{cl.BLUE} {Tools.humanformat(pps)}/s, "
                f"{cl.YELLOW}{t('Traffic (estimated)')}:{cl.BLUE} {Tools.humanbits(bps)}/s"
                f"{cl.RESET}"
            )

    netdiff = net_stats.tick()
    if netdiff is not None:
        total_pps, total_bps = netdiff
        total_bps *= 8
        pps_name = "Packets"

    logger.info(
        f"{cl.GREEN}{t('Total')}: "
        f"{cl.YELLOW}{t('Connections')}:{cl.GREEN} {Tools.humanformat(total_in_flight)}, "
        f"{cl.YELLOW}{t(pps_name)}:{cl.GREEN} {Tools.humanformat(total_pps)}/s, "
        f"{cl.YELLOW}{t('Traffic')}:{cl.GREEN} {Tools.humanbits(total_bps)}/s{cl.RESET}"
    )


def print_status(
    num_threads: int,
    use_my_ip: int,
    overtime: bool,
):
    if not use_my_ip:
        proxies_message = t('Using only proxies')
    elif use_my_ip == USE_ONLY_MY_IP:
        proxies_message = t('Using only your IP/VPN (no proxies)')
    else:
        proxies_message = t('Using both proxies and your IP/VPN')

    logger.info(
        f"{cl.YELLOW}{t('Threads')}: {cl.BLUE}{num_threads} | "
        f"{cl.MAGENTA}{proxies_message}{cl.RESET}"
    )

    if overtime:
        logger.warning(
            f"{cl.MAGENTA}{t('Delay in execution of operations detected')} - "
            f"{t('the attack continues, but we recommend reducing the workload')} `-t`{cl.RESET}"
        )
    print()


def print_banner(args):
    rows = []
    if not args.lang:
        rows.append(
            f"- {cl.YELLOW}Change language:{cl.BLUE} `--lang en` / `--lang ua`{cl.RESET}"
        )
    if not args.threads:
        rows.append(
            f"- {cl.YELLOW}{t('Workload (number of threads)')}:{cl.BLUE} {t('use flag `-t XXXX`, default is')} {DEFAULT_THREADS}"
        )
    elif args.threads > 10000 and args.copies == 1 and CPU_COUNT > 2:
        rows.append(
            f"- {cl.CYAN}{t('Instead of high `-t` value consider using')} {cl.YELLOW}`--copies 2`{cl.RESET}"
        )
    if not args.use_my_ip:
        rows.append(
            f"- {cl.MAGENTA}{t('Consider adding your IP/VPN to the attack - use flag `--vpn`')}{cl.RESET}"
        )
    rows.append(
        f"- {cl.YELLOW}{t('Complete documentation')}:{cl.RESET} - https://github.com/porthole-ascend-cinnamon/mhddos_proxy"
    )

    print()
    print(*rows, sep='\n')
    print()
