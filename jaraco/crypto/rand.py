import ctypes

import six

from .evp import lib


class RandError(Exception):
    pass


lib.RAND_bytes.argtypes = ctypes.c_char_p, ctypes.c_int
lib.RAND_pseudo_bytes.argtypes = ctypes.c_char_p, ctypes.c_int


def bytes(num, check_result=False):
    if num <= 0:
        raise ValueError("num must be > 0")
    bytes = ctypes.create_string_buffer(num)
    result = lib.RAND_bytes(bytes, num)
    if check_result and result == 0:
        msg = "Random Number Generator not seeded sufficiently"
        raise RandError(msg)
    return bytes.raw[:num]


def pseudo_bytes(num):
    if num <= 0:
        raise ValueError("num must be > 0")
    bytes = ctypes.create_string_buffer(num)
    lib.RAND_pseudo_bytes(bytes, num)
    return bytes.raw[:num]


lib.RAND_seed.argtypes = ctypes.c_char_p, ctypes.c_int
lib.RAND_add.argtypes = ctypes.c_char_p, ctypes.c_int, ctypes.c_double


def seed(data, entropy=None):
    if not isinstance(data, six.string_types):
        raise TypeError("data must be a string")
    params = [data, len(data)]
    if entropy:
        func = lib.RAND_add
        params.append(entropy)
    else:
        func = lib.RAND_seed
    func(*params)


status = lib.RAND_status
