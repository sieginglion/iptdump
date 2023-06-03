import select
import subprocess
import sys
from time import sleep

from loguru import logger


def run(cmd: str):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if r.returncode != 0 or r.stderr:
        logger.critical(r.stderr)
        sys.exit(r.returncode)
    return r


def clear_traces():
    for chain in ['PREROUTING', 'OUTPUT']:
        run(
            f'iptables -t raw -L {chain} --line-numbers | grep TRACE | awk \'{{ print $1 }}\' | sort -r | xargs -I {{}} iptables -t raw -D {chain} {{}}',
        )


def add_traces(filter: str):
    for chain in ['PREROUTING', 'OUTPUT']:
        run(f'iptables -t raw -I {chain} 1 {filter} -j TRACE')


def poll_dmesg():
    proc = subprocess.Popen(['dmesg', '-W'], stdout=subprocess.PIPE, text=True)
    assert proc.stdout
    while True:
        logger.info(proc.stdout.readline())
        sleep(0.1)


if __name__ == '__main__':
    poll_dmesg()
