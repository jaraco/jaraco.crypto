import ctypes
import os
import platform
import subprocess

from six.moves import filter


def find_lib_Linux(lib_name):
    try:
        lines = subprocess.check_output(['ldconfig', '-p'], text=True)
    except TypeError:
        lines = subprocess.check_output(['ldconfig', '-p'], universal_newlines=True)

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
    Given a name like libeay32, find the best match.
    """
    # todo, allow the target environment to customize this behavior
    roots = [
        'c:\\Program Files\\OpenSSL\\',
        '\\OpenSSL-Win64',
        '/usr/local/opt/openssl/lib/',
    ]
    ext = (
        '.dll'
        if platform.system() == 'Windows'
        else '.dylib'
        if platform.system() == 'Darwin'
        else '.so'
    )
    filename = lib_name + ext
    return next(_find_file(filename, roots), None)


def _find_file(filename, roots):
    candidates = (os.path.join(root, filename) for root in roots)
    return filter(os.path.exists, candidates)
