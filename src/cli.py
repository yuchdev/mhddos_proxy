import argparse
import random
from multiprocessing import cpu_count

from .core import THREADS_PER_CORE, MAX_DEFAULT_THREADS, ONLY_MY_IP
from .mhddos import Methods, AttackSettings


def init_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'targets',
        nargs='*',
        help='List of targets, separated by spaces',
    )
    parser.add_argument(
        '-c',
        '--config',
        help='URL or local path to file with attack targets',
    )
    parser.add_argument(
        '-t',
        '--threads',
        type=int,
        default=min(THREADS_PER_CORE * cpu_count(), MAX_DEFAULT_THREADS),
        help=f'Total number of threads to run (default is CPU * {THREADS_PER_CORE})',
    )
    parser.add_argument(
        '--rpc',
        type=int,
        default=2000,
        help='How many requests to send on a single proxy connection (default is 2000)',
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        default=False,
        help='Print log as text',
    )
    parser.add_argument(
        '--table',
        action='store_true',
        default=False,
        help='Print log as table',
    )
    parser.add_argument(
        '--vpn',
        dest='use_my_ip',
        const=10,
        default=0,
        nargs='?',
        type=int,
        action='store',
        help='Use both my IP and proxies for the attack. '
             'Optionally, specify a percent of using my IP (default is 10%%)',
    )
    parser.add_argument(
        '--http-methods',
        nargs='+',
        type=str.upper,
        default=['GET', random.choice(['POST', 'STRESS'])],
        choices=Methods.LAYER7_METHODS,
        help='List of HTTP(s) attack methods to use. Default is GET + POST|STRESS',
    )
    parser.add_argument(
        '--proxies',
        help='URL or local path to file with proxies to use',
    )
    parser.add_argument(
        '--itarmy',
        action='store_true',
        default=False,
    )
    parser.add_argument(
        '--advanced-allow-uvloop',
        action='store_true',
        default=False,
        help='Advanced setting. Allows the system to switch to the optimized implementation of the event loop (when available)'
    )
    parser.add_argument(
        '--advanced-default-transport',
        type=str,
        default=AttackSettings.TRANSPORT_PROTO,
        choices=["stream", "sock", "proto"],
        help='For testing purposes only'
    )

    parser.add_argument('-p', '--period', type=int, help='DEPRECATED')
    parser.add_argument('--proxy-timeout', type=float, help='DEPRECATED')
    parser.add_argument('--udp-threads', type=int, help='DEPRECATED')
    return parser
