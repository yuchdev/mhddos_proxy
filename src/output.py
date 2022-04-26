import os
from typing import Dict, Tuple

from tabulate import tabulate

from .core import cl, logger, THREADS_PER_CORE, Stats
from .mhddos import Tools
from .targets import Target


def cls():
    os.system('cls' if os.name == 'nt' else 'clear')


def show_statistic(
    statistics: Dict[Tuple[Target, str], Stats],
    refresh_rate,
    table,
    vpn_mode,
    num_proxies,
    period,
    passed,
    next_targets_load,
):
    tabulate_text = []
    total_pps, total_bps, total_in_flight = 0, 0, 0
    for (target, method), stats in statistics.items():
        rs, bs, in_flight_conn = stats.reset()
        pps = int(rs / refresh_rate)
        total_pps += pps
        total_in_flight += in_flight_conn
        bps = int(8 * bs / refresh_rate)
        total_bps += bps
        if table:
            tabulate_text.append((
                f'{cl.YELLOW}%s' % target.url.host, target.url.port, method,
                Tools.humanformat(pps) + "/s", f'{Tools.humanbits(bps)}/s{cl.RESET}'
            ))
        else:
            logger.info(
                f"{cl.YELLOW}Ціль:{cl.BLUE} {target.url.host}, "
                f"{cl.YELLOW}Порт:{cl.BLUE} {target.url.port}, "
                f"{cl.YELLOW}Метод:{cl.BLUE} {method}, "
                # XXX: add in flight connections to the table
                f"{cl.YELLOW}Зʼєднань:{cl.BLUE} {Tools.humanformat(in_flight_conn)}, "
                f"{cl.YELLOW}Запити:{cl.BLUE} {Tools.humanformat(pps)}/s, "
                f"{cl.YELLOW}Трафік:{cl.BLUE} {Tools.humanbits(bps)}/s"
                f"{cl.RESET}"
            )

    if table:
        tabulate_text.append((f'{cl.GREEN}Усього', '', '', Tools.humanformat(total_pps) + "/s",
                              f'{Tools.humanbits(total_bps)}/s{cl.RESET}'))

        cls()
        print(tabulate(
            tabulate_text,
            headers=[f'{cl.BLUE}Ціль', 'Порт', 'Метод', 'Запити', f'Трафік{cl.RESET}'],
            tablefmt='fancy_grid'
        ))
        print_banner(vpn_mode)
    else:
        logger.info(
            f"{cl.GREEN}Усього: "
            f"{cl.YELLOW}Зʼєднань:{cl.GREEN} {Tools.humanformat(total_in_flight)}, "
            f"{cl.YELLOW}Запити:{cl.GREEN} {Tools.humanformat(total_pps)}/s, "
            f"{cl.YELLOW}Трафік:{cl.GREEN} {Tools.humanbits(total_bps)}/s{cl.RESET}"
        )

    print_progress(num_proxies, next_targets_load)


def print_progress(num_proxies, next_targets_load):
    logger.info(
        f"{cl.YELLOW}Оновлення цілей через: {cl.BLUE}{next_targets_load} секунд{cl.RESET}")
    if num_proxies:
        logger.info(f'{cl.YELLOW}Кількість проксі: {cl.BLUE}{num_proxies}{cl.RESET}')
    else:
        logger.info(f'{cl.YELLOW}Атака без проксі - переконайтеся що ви анонімні{cl.RESET}')


def print_banner(vpn_mode):
    print(f'''
- {cl.YELLOW}Навантаження (кількість потоків){cl.RESET} - параметр `-t 3000`, за замовчуванням - CPU * {THREADS_PER_CORE}
- {cl.YELLOW}Статистика у вигляді таблиці або тексту{cl.RESET} - прапорець `--table` або `--debug`
- {cl.YELLOW}Повна документація{cl.RESET} - https://github.com/porthole-ascend-cinnamon/mhddos_proxy
    ''')

    if not vpn_mode:
        print(
            f'        {cl.MAGENTA}Щоб використовувати VPN або власний IP замість проксі - додайте прапорець `--vpn`{cl.RESET}\n')
