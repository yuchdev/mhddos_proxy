import os
from typing import List

from tabulate import tabulate

from .core import DEFAULT_THREADS, cl, logger
from .mhddos import Tools
from .targets import TargetStats


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
                f"{cl.YELLOW}Ціль:{cl.BLUE} {target.human_repr()}, "
                f"{cl.YELLOW}Порт:{cl.BLUE} {target.url.port}, "
                f"{cl.YELLOW}Метод:{cl.BLUE} {method}{method_sig}, "
                f"{cl.YELLOW}Зʼєднань:{cl.BLUE} {Tools.humanformat(in_flight_conn)}, "
                f"{cl.YELLOW}Запити:{cl.BLUE} {Tools.humanformat(pps)}/s, "
                f"{cl.YELLOW}Трафік:{cl.BLUE} {Tools.humanbits(bps)}/s"
                f"{cl.RESET}"
            )

    if table:
        tabulate_text.append((
            f'{cl.GREEN}Усього',
            '',
            '',
            Tools.humanformat(total_in_flight),
            Tools.humanformat(total_pps) + "/s",
            f'{Tools.humanbits(total_bps)}/s{cl.RESET}'
        ))

        cls()
        print(tabulate(
            tabulate_text,
            headers=[f'{cl.BLUE}Ціль', 'Порт', 'Метод', 'Зʼєднань', 'Запити', f'Трафік{cl.RESET}'],
            tablefmt='fancy_grid'
        ))
        print_banner(use_my_ip)
    else:
        logger.info(
            f"{cl.GREEN}Усього: "
            f"{cl.YELLOW}Зʼєднань:{cl.GREEN} {Tools.humanformat(total_in_flight)}, "
            f"{cl.YELLOW}Запити:{cl.GREEN} {Tools.humanformat(total_pps)}/s, "
            f"{cl.YELLOW}Трафік:{cl.GREEN} {Tools.humanbits(total_bps)}/s{cl.RESET}"
        )

    print_progress(num_proxies, use_my_ip, overtime)


def print_progress(
    num_proxies: int,
    use_my_ip: int,
    overtime: bool,
):
    if num_proxies:
        logger.info(f"{cl.YELLOW}Кількість проксі: {cl.BLUE}{num_proxies}{cl.RESET}")
        if use_my_ip:
            logger.info(
                f"{cl.YELLOW}Атака також використовує {cl.MAGENTA}"
                f"ваш IP разом з проксі{cl.RESET}")
    else:
        logger.info(
            f"{cl.YELLOW}Атака {cl.MAGENTA}без проксі{cl.YELLOW} - "
            f"використовується тільки ваш IP{cl.RESET}")

    if overtime:
        logger.warning(
            f"{cl.MAGENTA}Зафіксована затримка у виконанні операцій - "
            f"атака продовжується, але радимо зменшити значення налаштування `-t`{cl.RESET}")


def print_banner(use_my_ip):
    print(f'''
- {cl.YELLOW}Навантаження (кількість потоків){cl.RESET} - параметр `-t 5000`, за замовчуванням - {DEFAULT_THREADS}
- {cl.YELLOW}Статистика у вигляді таблиці або тексту{cl.RESET} - прапорець `--table` або `--debug`
- {cl.YELLOW}Повна документація{cl.RESET} - https://github.com/porthole-ascend-cinnamon/mhddos_proxy
    ''')

    if not use_my_ip:
        print(
            f'        {cl.MAGENTA}Використовувати свій IP або VPN {cl.YELLOW}на додачу до проксі - прапорець `--vpn`{cl.RESET}\n')
