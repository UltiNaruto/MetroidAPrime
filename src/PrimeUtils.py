import io
import os
import pkgutil
import platform
import sys

from importlib.metadata import version, PackageNotFoundError
from typing import List

from .Enum import SuitUpgrade


LIBS: dict[str, dict[str, dict[str, str]|str]] = {
    'py_randomprime': {
        'links': {
            'windows': 'https://files.pythonhosted.org/packages/10/02/db0f939d37c95a91aed5cb7c28e7b2f4bc71b63a49be2a1ea4d23e3a713b/py_randomprime-1.31.1-cp310-abi3-win_amd64.whl',
            'linux': 'https://files.pythonhosted.org/packages/3b/a8/84953c96781ff7e1b6d03d560b708d128d1fcca5260965df2f7fa92df428/py_randomprime-1.31.1-cp310-abi3-manylinux_2_28_x86_64.whl',
            'darwin-arm': 'https://files.pythonhosted.org/packages/6f/db/c5ae06636f6b8ddfadbe99fb40e0fc144a9f86638b8e2c47220d8bd9db17/py_randomprime-1.31.1-cp310-abi3-macosx_11_0_arm64.whl',
            'darwin-intel': 'https://files.pythonhosted.org/packages/0a/21/e2e294b2728174a2d6f1a9c271963ab5eb6f43fd9f6270ad7e2094ece3de/py_randomprime-1.31.1-cp310-abi3-macosx_10_12_x86_64.whl',
        },
        'version': '1.31.1',
    },
    'ppc_asm': {
        'links': {
            ope_sys: 'https://files.pythonhosted.org/packages/3e/4c/c2eed780f32fc5b77c5b6c33bdf1792dc362e838f2bb3491dd486a329ecc/ppc_asm-1.9.0-py3-none-any.whl'
            for ope_sys in ['windows', 'linux', 'darwin-arm', 'darwin-intel']
        },
        'version': '1.9.0',
    }
}


def setup_libs():
    """Downloads the libraries if they are not present."""
    import shutil
    import requests
    import zipfile
    import Utils

    lib_path = Utils.home_path('lib')
    if not Utils.is_windows and lib_path not in sys.path:
        sys.path.append(lib_path)

    ope_sys = '???'
    if Utils.is_windows:
        ope_sys = 'windows'
    elif Utils.is_linux:
        ope_sys = 'linux'
    elif Utils.is_macos:
        ope_sys = 'darwin-'
        try:
            match platform.machine():
                case 'x86_64':
                    ope_sys += 'intel'
                case 'arm64':
                    ope_sys += 'arm'
                case v:
                    raise RuntimeError(f'No idea what Mac OS version is {v} :S')
        except RuntimeError as ex:
            print(str(ex))
            raise ex

    for lib_name, lib in LIBS.items():
        full_lib_path = os.path.join(lib_path, lib_name)

        try:
            if version(lib_name.replace('_', '-')) != lib['version']:
                raise RuntimeError('Wrong version')
        except (ImportError, RuntimeError, PackageNotFoundError):
            # delete if it already exists
            if os.path.isdir(full_lib_path):
                shutil.rmtree(full_lib_path)
            if os.path.isdir(f"{full_lib_path}-*.dist-info"):
                shutil.rmtree(f"{full_lib_path}-*.dist-info")

            if not Utils.is_frozen():
                import subprocess
                subprocess.check_call([
                    sys.executable,
                    '-m',
                    'pip',
                    'install',
                    '--upgrade',
                    f'{lib_name.replace("_", "-")}=={lib["version"]}',
                    '--target',
                    lib_path,
                ])
            else:
                print(f'Downloading {lib_name}...')
                assert ope_sys != "???"
                with requests.get(lib['links'][ope_sys]) as r:
                    r.raise_for_status()
                    z = zipfile.ZipFile(io.BytesIO(r.content))
                    z.extractall(lib_path)


def get_apworld_version():
    # Get version from ./version.txt
    # detect if on windows since pathing is handled differently from linux
    if platform.system() == "Windows":
        path = os.path.join(str(os.path.dirname(__file__)), "version.txt")
    else:
        path = "version.txt"
    ver = pkgutil.get_data(__name__, path)
    assert ver is not None
    ver = ver.decode().strip()
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

def is_between_or_throw(v: int, minimum: int, maximum: int) -> int:
    if v < minimum or v > maximum:
        raise RuntimeError(f'{v} is not between {minimum} and {maximum}!')
    return v
