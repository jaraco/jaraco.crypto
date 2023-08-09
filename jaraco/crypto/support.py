import ctypes
import os
import platform
import subprocess
import glob
import contextlib
import itertools


def _run_cmd(cmd):
    return subprocess.check_output(cmd.split(' '), text=True, encoding='utf-8')


def find_lib_Linux(lib_name):
    for line in _run_cmd('ldconfig -p').splitlines():
        lib, _, rest = line.strip().partition(' ')
        _, _, path = rest.rpartition(' ')
        found_name, _, _ = lib.partition('.')
        if lib_name == found_name:
            return path


def find_library(lib_name):
    """
    Given a name like libcrypto, find the best match and load it.
    """
    func = globals()[f'find_lib_{platform.system()}']
    found = func(lib_name)
    return found and ctypes.cdll.LoadLibrary(found)


def _brew_paths():
    with contextlib.suppress(subprocess.CalledProcessError):
        yield _run_cmd('brew --prefix openssl').strip() + '/lib'


def find_lib_Darwin(lib_name):
    heuristic_paths = [
        '/usr/local/opt/openssl/lib/',
    ]
    search_paths = itertools.chain(_brew_paths(), heuristic_paths)
    return _search(lib_name, search_paths, '.dylib')


def find_lib_Windows(lib_name):
    """
    Default OpenSSL installs to the Windows system folder and are
    reachable without a path or extension, but must have the right
    name.
    """
    heuristic_paths = [
        'C:\\Program Files\\OpenSSL',
        '\\OpenSSL-Win64',
        'C:\\Program Files\\OpenSSL-Win64-ARM',
    ]
    search_paths = os.environ['PATH'].split(os.pathsep) + heuristic_paths
    return _search(lib_name, search_paths, '.dll')


def _search(lib_name, paths, ext):
    names = (
        name
        for path in paths
        for name in glob.glob(path + os.sep + f'{lib_name}*{ext}')
    )

    return next(names, None)
