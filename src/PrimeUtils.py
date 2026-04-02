import os
import pkgutil
import platform
import sys

from importlib.metadata import version, PackageNotFoundError
from typing import List

from .Items import SuitUpgrade


LIBS: dict[str, str] = {
    'py-randomprime': '1.30.4',
    'ppc-asm': '1.2.1',
}


def setup_libs():
    """Downloads the libraries if they are not present."""
    import Utils

    lib_path = Utils.home_path('lib')
    if not Utils.is_windows and lib_path not in sys.path:
        sys.path.append(lib_path)

    for lib, v in LIBS.items():
        try:
            if version(lib) != v:
                raise RuntimeError('Wrong version')
        except (ImportError, RuntimeError, PackageNotFoundError):
            import glob
            import subprocess
            import shutil

            if os.path.isdir(os.path.join(lib_path, lib.replace('-', '_'))):
                shutil.rmtree(os.path.join(lib_path, lib.replace('-', '_')))

            dirs_to_delete = glob.glob(os.path.join(lib_path, f"{lib.replace('-', '_')}-*.dist-info"))
            for d in dirs_to_delete:
                shutil.rmtree(d)

            subprocess.check_call([
                'python' if Utils.is_windows else 'python3',
                '-m',
                'pip',
                'install',
                '--upgrade',
                f'{lib}=={v}',
                '--target',
                lib_path,
            ])


def get_apworld_version():
    # Get version from ./version.txt
    # detect if on windows since pathing is handled differently from linux
    if platform.system() == "Windows":
        path = os.path.join(os.path.dirname(__file__), "version.txt")
    else:
        path = "version.txt"
    ver = pkgutil.get_data(__name__, path).decode().strip()
    return ver

def count_ammo(items: List[str], main: str, expansion: str, requires_main: bool) -> int:
    has_main: bool = main in [item for item in items if item == main]
    ammo_with_main: int = 0
    expansion_count: int = sum([1 for item in items if item == expansion])
    ammo_per_expansion: int = 0

    if main == str(SuitUpgrade.Main_Power_Bomb):
        ammo_with_main = 4
        ammo_per_expansion = 1
    if main == str(SuitUpgrade.Missile_Launcher):
        ammo_with_main = 5
        ammo_per_expansion = 5

    result: int = 0
    if requires_main:
        if not has_main:
            return result
        else:
            result += ammo_with_main + expansion_count * ammo_per_expansion
    else:
        if has_main:
            result += ammo_with_main
        elif expansion_count > 0:
            result += ammo_with_main
            expansion_count -= 1
        result += expansion_count * ammo_per_expansion

    return result
