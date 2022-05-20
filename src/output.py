import os
from typing import List
from tabulate import tabulate

from .core import DEFAULT_THREADS, cl, logger
from .mhddos import Tools
from .targets import TargetStats
from .translations import TR


def cls():
    os.system('cls' if os.name == 'nt' else 'clear')


def show_statistic(
    statistics: List[TargetStats],
    table: bool,
    use_my_ip: int,
    num_proxies: int,
    overtime: bool,
):
    tabulate_text = []
    total_pps, total_bps, total_in_flight = 0, 0, 0
    for stats in statistics:
        (target, method, sig) = stats.target
        method_sig = f" ({sig})" if sig is not None else ""
        pps, bps, in_flight_conn = stats.reset()
        total_pps += pps
        total_bps += bps
        total_in_flight += in_flight_conn
        if table:
            tabulate_text.append((
                f'{cl.YELLOW}%s' % target.url.host,
                target.url.port,
                method,
                Tools.humanformat(in_flight_conn),
                Tools.humanformat(pps) + "/s",
                f'{Tools.humanbits(bps)}/s{cl.RESET}'
            ))
        else:
            logger.info(
                f"{cl.YELLOW}{TR('Target')}:{cl.BLUE} {target.human_repr()}, "
                f"{cl.YELLOW}{TR('Port')}:{cl.BLUE} {target.url.port}, "
                f"{cl.YELLOW}{TR('Method')}:{cl.BLUE} {method}{method_sig}, "
                f"{cl.YELLOW}{TR('Connections')}:{cl.BLUE} {Tools.humanformat(in_flight_conn)}, "
                f"{cl.YELLOW}{TR('Requests')}:{cl.BLUE} {Tools.humanformat(pps)}/s, "
                f"{cl.YELLOW}{TR('Traffic')}:{cl.BLUE} {Tools.humanbits(bps)}/s"
                f"{cl.RESET}"
            )

    if table:
        tabulate_text.append((
            f"{cl.GREEN}{TR('Total')}",
            '',
            '',
            Tools.humanformat(total_in_flight),
            Tools.humanformat(total_pps) + "/s",
            f'{Tools.humanbits(total_bps)}/s{cl.RESET}'
        ))

        cls()
        print(tabulate(
            tabulate_text,
            headers=[
                f"{cl.BLUE}{TR('Target')}",
                {TR('Port')},
                {TR('Method')},
                {TR('Connections')},
                {TR('Requests')},
                f"{TR('Traffic')}{cl.RESET}"],
            tablefmt='fancy_grid'
        ))
        print_banner(use_my_ip)
    else:
        logger.info(
            f"{cl.GREEN}{TR('Total')}: "
            f"{cl.YELLOW}{TR('Connections')}:{cl.GREEN} {Tools.humanformat(total_in_flight)}, "
            f"{cl.YELLOW}{TR('Requests')}:{cl.GREEN} {Tools.humanformat(total_pps)}/s, "
            f"{cl.YELLOW}{TR('Traffic')}:{cl.GREEN} {Tools.humanbits(total_bps)}/s{cl.RESET}"
        )

    print_progress(num_proxies, use_my_ip, overtime)


def print_progress(
    num_proxies: int,
    use_my_ip: int,
    overtime: bool,
):
    if num_proxies:
        logger.info(f"{cl.YELLOW}{TR('Number of proxies')}: {cl.BLUE}{num_proxies}{cl.RESET}")
        if use_my_ip:
            logger.info(
                f"{cl.YELLOW}{TR('The attack also uses')} {cl.MAGENTA}"
                f"{TR('your IP alongside with the proxy')}{cl.RESET}")
    else:
        logger.info(
            f"{cl.YELLOW}{TR('Attack')} {cl.MAGENTA}{TR('without a proxy')}{cl.YELLOW} - "
            f"{TR('only your IP is used')}{cl.RESET}")

    if overtime:
        logger.warning(
            f"{cl.MAGENTA}{TR('Delay in execution of operations detected')} - "
            f"{TR('the attack continues, but we recommend reducing the workload')} `-t`{cl.RESET}")


def print_banner(use_my_ip):
    print(f'''
- {cl.YELLOW}{TR('Workload (number of threads)')}{cl.RESET} - {TR('parameter `-t 5000` is default')} - {DEFAULT_THREADS}
- {cl.YELLOW}{TR('Show statistics as a table or text')}{cl.RESET} - {TR('the `--table` or` --debug` flags')}
- {cl.YELLOW}{TR('Complete documentation')}{cl.RESET} - https://github.com/porthole-ascend-cinnamon/mhddos_proxy
    ''')

    if not use_my_ip:
        print(
            f"\t{cl.MAGENTA}{TR('Use your IP or VPN')} {cl.YELLOW}{TR('in addition to the proxy use flag `--vpn` to enable your IP or VPN')}{cl.RESET}\n"
        )
