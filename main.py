import re
import subprocess
import sys
from dataclasses import dataclass, field, fields
from signal import SIGINT, signal
from types import FrameType
from typing import Union

from rich import print
from typer import Argument, Typer
from typing_extensions import Annotated

app = Typer(add_completion=False)


@dataclass
class Trace:
    IN: str
    OUT: str
    SRC: str
    DST: str
    PROTO: str
    REF: str = field(repr=False)
    RULE: str = field(init=False)

    def __post_init__(self):
        table, chain, _, index = self.REF.split(':')
        r = run(f'iptables -t {table} -nL {chain} {index}')
        self.RULE = re.sub(r'\s+', ' ', r.stdout.decode().strip())  # type: ignore


def run(cmd: str):
    r = subprocess.run(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    if r.returncode != 0 or r.stderr:
        print(f'[red]{r.stderr.decode()}', file=sys.stderr)
        sys.exit(r.returncode)
    return r


def clear_traces(signum: Union[int, None] = None, frame: Union[FrameType, None] = None):
    for chain in ['PREROUTING', 'OUTPUT']:
        run(
            f'iptables -t raw -L {chain} --line-numbers | grep TRACE | awk \'{{ print $1 }}\' | sort -r | xargs -I {{}} iptables -t raw -D {chain} {{}}'
        )
    if signum:
        sys.exit()


def add_traces(match_rule: str):
    for chain in ['PREROUTING', 'OUTPUT']:
        run(f'iptables -t raw -I {chain} 1 {match_rule} -j TRACE')


def parse_log(log: str):
    T = re.split(r'\s+', log)
    K = [f.name for f in fields(Trace)]
    D: dict[str, str] = {}
    for t in T:
        if '=' in t:
            k, v = t.split('=')
            if k in K:
                D[k] = v
        elif 'rule:' in t:
            D['REF'] = t
    return Trace(**D)


def poll_then_log():
    run('dmesg -C')
    proc = subprocess.Popen(['dmesg', '-w'], stdout=subprocess.PIPE)
    assert proc.stdout
    while True:
        log = proc.stdout.readline().decode()
        if not re.search(r'TRACE:.+rule:', log):
            continue
        print(parse_log(log))


@app.command()
def main(
    match_rule: Annotated[
        str, Argument(help='Will be passed to iptables to match packets.')
    ]
):
    clear_traces()
    add_traces(match_rule)
    poll_then_log()


if __name__ == '__main__':
    signal(SIGINT, clear_traces)
    app(prog_name='iptdump')
