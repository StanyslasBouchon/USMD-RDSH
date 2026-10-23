"""Bundle a USMD-RDSH node into one archive to copy onto a machine with scp.

    python scripts/package.py                 dist/usmd-rdsh-<version>.tar.gz
    python scripts/package.py --offline       same, with every dependency wheel
                                              (Linux x86_64, CPython 3.13)
    python scripts/package.py --offline --arch aarch64
    python scripts/package.py --offline --with-python
                                              also a standalone CPython 3.13, for
                                              machines without Python >= 3.13

The archive holds the usmd-rdsh and nan-actions wheels, the runtime
requirements and install.sh (scripts/bundle-install.sh). On the machine:

    scp dist/usmd-rdsh-<version>.tar.gz user@host:
    ssh user@host 'tar xzf usmd-rdsh-<version>.tar.gz && usmd-rdsh-<version>/install.sh'

nan-actions is a local path dependency (../nan-actions): the usmd-rdsh wheel
is installed without its dependencies and requirements.txt lists the others.
"""

import argparse
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "scripts" / "bundle-install.sh"
# Dependencies of pyproject.toml that a running node does not need.
EXCLUDED = {"nan-actions", "pytest"}
PYTHON_VERSION = "3.13"
# Relocatable CPython builds, the ones uv installs.
STANDALONE_RELEASE = (
    "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest")


def _project(path: Path) -> dict:
    with (path / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)["project"]


def _name(requirement: str) -> str:
    for separator in "<>=!~;[@ ":
        requirement = requirement.split(separator, 1)[0]
    return requirement.strip().lower().replace("_", "-")


def _requirements(*projects: dict) -> list[str]:
    seen: dict[str, str] = {}
    for project in projects:
        for requirement in project.get("dependencies", []):
            name = _name(requirement)
            if name not in EXCLUDED:
                seen.setdefault(name, requirement)
    return list(seen.values())


def _pip(*args: str) -> None:
    subprocess.run([sys.executable, "-m", "pip", "--disable-pip-version-check", *args],
                   check=True)


def _platforms(arch: str) -> list[str]:
    return [f"manylinux_2_28_{arch}", f"manylinux_2_17_{arch}", f"manylinux2014_{arch}",
            "linux_" + arch]


def _standalone_python(arch: str, cache: Path) -> Path:
    """Latest standalone CPython 3.13 for Linux ``arch``, downloaded once into ``cache``."""
    pattern = re.compile(re.escape(f"cpython-{PYTHON_VERSION}.") + r"\d+\+\d+-"
                         + re.escape(f"{arch}-unknown-linux-gnu-install_only_stripped.tar.gz"))
    with urllib.request.urlopen(STANDALONE_RELEASE) as response:
        release = json.load(response)
    assets = [a for a in release["assets"] if pattern.fullmatch(a["name"])]
    if not assets:
        raise SystemExit(f"no standalone CPython {PYTHON_VERSION} for {arch} in release "
                         f"{release['tag_name']}")
    asset = assets[0]
    target = cache / asset["name"]
    if not target.is_file():
        cache.mkdir(parents=True, exist_ok=True)
        print(f"downloading {asset['name']} ({asset['size'] // 2**20} MiB)")
        partial = target.with_suffix(".part")
        urllib.request.urlretrieve(asset["browser_download_url"], partial)
        partial.replace(target)
    return target


def _add_text(archive: tarfile.TarFile, name: str, text: str, mode: int = 0o644) -> None:
    # Unix line endings whatever git's autocrlf did to the working tree.
    data = text.replace("\r\n", "\n").encode()
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    archive.addfile(info, io.BytesIO(data))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--nan-actions", type=Path, default=ROOT.parent / "nan-actions",
                        metavar="DIR", help="nan-actions checkout (default ../nan-actions)")
    parser.add_argument("--offline", action="store_true",
                        help="include every dependency wheel (install without internet)")
    parser.add_argument("--with-python", action="store_true",
                        help=f"include a standalone CPython {PYTHON_VERSION} (used by install.sh)")
    parser.add_argument("--arch", default="x86_64",
                        help="with --offline or --with-python: target architecture "
                             "(x86_64, aarch64)")
    parser.add_argument("-o", "--output", type=Path, default=ROOT / "dist", metavar="DIR")
    args = parser.parse_args()

    nan_actions = args.nan_actions.resolve()
    if not (nan_actions / "pyproject.toml").is_file():
        raise SystemExit(f"nan-actions not found in {nan_actions} (use --nan-actions)")

    usmd = _project(ROOT)
    requirements = _requirements(usmd, _project(nan_actions))
    bundle = f"usmd-rdsh-{usmd['version']}"

    with tempfile.TemporaryDirectory() as tmp:
        wheels = Path(tmp) / "wheels"
        _pip("wheel", "--quiet", "--no-deps", "-w", str(wheels), str(ROOT), str(nan_actions))
        if args.offline:
            requirements_file = Path(tmp) / "requirements.txt"
            requirements_file.write_text("\n".join(requirements) + "\n", encoding="utf-8")
            platforms = [f"--platform={p}" for p in _platforms(args.arch)]
            _pip("download", "--quiet", "--only-binary=:all:", *platforms,
                 f"--python-version={PYTHON_VERSION}", "--implementation=cp",
                 "-d", str(wheels), "-r", str(requirements_file))

        args.output.mkdir(parents=True, exist_ok=True)
        target = args.output / f"{bundle}.tar.gz"
        with tarfile.open(target, "w:gz") as archive:
            _add_text(archive, f"{bundle}/install.sh",
                      INSTALLER.read_text(encoding="utf-8"), mode=0o755)
            _add_text(archive, f"{bundle}/requirements.txt", "\n".join(requirements) + "\n")
            if args.offline:
                _add_text(archive, f"{bundle}/wheels/OFFLINE",
                          f"linux {args.arch}, CPython {PYTHON_VERSION}\n")
            if args.with_python:
                python = _standalone_python(args.arch, args.output / "cache")
                archive.add(python, f"{bundle}/python.tar.gz")
            for wheel in sorted(wheels.glob("*.whl")):
                archive.add(wheel, f"{bundle}/wheels/{wheel.name}")

    size = target.stat().st_size / 1024
    print(f"{target} ({size:.0f} KiB)")
    print(f"  scp {target} user@host:")
    print(f"  ssh user@host 'tar xzf {target.name} && {bundle}/install.sh'")


if __name__ == "__main__":
    main()
