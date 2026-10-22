"""A development cluster: several virtual nodes on this machine.

    python -m usmd_rdsh.dev --nodes 3          start nodes 1..3, then wait
    python -m usmd_rdsh.dev --nodes 3 --reset  start from a clean .usmd-dev/

Each node runs in its own process (``usmd --dev N --no-console``) on its own
loopback address 127.0.0.(N+1); node 1 founds the USD, the others join it.
Ctrl+C stops them all. A console on one node: ``usmd --dev 2`` in another
terminal is refused while that node runs - use its web interface, or
``usmd --dev 2 -c "show node"`` for a one-shot look at its saved state.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time

from usmd_rdsh.cli.startup import DEV_ROOT, dev_address


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m usmd_rdsh.dev")
    parser.add_argument("--nodes", type=int, default=3, help="how many virtual nodes (1-250)")
    parser.add_argument("--reset", action="store_true", help="delete .usmd-dev/ first")
    args = parser.parse_args(argv)
    if not 1 <= args.nodes <= 250:
        raise SystemExit("--nodes is between 1 and 250")
    if args.reset and DEV_ROOT.exists():
        shutil.rmtree(DEV_ROOT)
    DEV_ROOT.mkdir(exist_ok=True)

    processes = []
    try:
        for index in range(1, args.nodes + 1):
            command = [sys.executable, "-u", "-m", "usmd_rdsh.main", "--dev", str(index),
                       "--dev-nodes", str(args.nodes), "--no-console"]
            log = open(DEV_ROOT / f"node{index}.log", "a", encoding="utf-8")  # pylint: disable=consider-using-with
            processes.append(subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT))
            print(f"node {index}: {dev_address(index)}  web http://{dev_address(index)}:8080/"
                  f"  (admin / admin)  log {DEV_ROOT / f'node{index}.log'}")
            if index == 1:
                time.sleep(3)  # node 1 creates the shared authority and the USD
        print("Ctrl+C to stop the cluster.")
        while all(p.poll() is None for p in processes):
            time.sleep(1)
        for index, process in enumerate(processes, start=1):
            if process.poll() is not None:
                print(f"node {index} exited with code {process.returncode}: "
                      f"see {DEV_ROOT / f'node{index}.log'}")
    except KeyboardInterrupt:
        pass
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    main()
