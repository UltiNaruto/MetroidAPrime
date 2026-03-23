import os
import pkgutil
import platform
import sys

from importlib.metadata import version, PackageNotFoundError


LIBS: dict[str, str] = {
    'py-randomprime': '1.30.4',
    'ppc-asm': '1.2.1',
}


def setup_libs():
    """Downloads the libraries if they are not present."""
    import importlib
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
    version = pkgutil.get_data(__name__, path).decode().strip()
    return version
