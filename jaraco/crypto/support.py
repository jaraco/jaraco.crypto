import ctypes
import os
import platform
import subprocess
import glob


def find_lib_Linux(lib_name):
    lines = subprocess.check_output(['ldconfig', '-p'], text=True, encoding='utf-8')

    for line in lines.splitlines():
        lib, _, rest = line.strip().partition(' ')
        _, _, path = rest.rpartition(' ')
        found_name, _, _ = lib.partition('.')
        if lib_name == found_name:
            return path


def find_library(lib_name):
    func = globals().get(f'find_lib_{platform.system()}', find_lib_default)
    found = func(lib_name)
    return found and ctypes.cdll.LoadLibrary(found)


def find_lib_default(lib_name):
    """
    Given a name like libcrypto, find the best match.
    """
    # todo, allow the target environment to customize this behavior
    roots = [
        '/usr/local/opt/openssl/lib/',
        '/opt/homebrew/lib/',
    ]
    ext = '.dylib' if platform.system() == 'Darwin' else '.so'
    filename = lib_name + ext
    return next(_find_file(filename, roots), None)


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


def _find_file(filename, roots):
    candidates = (os.path.join(root, filename) for root in roots)
    return filter(os.path.exists, candidates)
