from ctypes import *

import ctypescrypto

class RandError(Exception):
    pass

def bytes(libcrypto, num, check_result=False):
    if num <= 0 :
        raise ValueError, "'num' should be > 0"
    buffer = create_string_buffer(num)
    try :
        result = libcrypto.RAND_bytes(byref(buffer), num) 
        if check_result and result == 0:
            raise RandError, "Random Number Generator not seeded sufficiently"
        return buffer.raw[:num]
    finally :
        _free_buffer(libcrypto, buffer)

def pseudo_bytes(libcrypto, num):
    if num <= 0 :
        raise ValueError, "'num' should be > 0"
    buffer = create_string_buffer(num)
    try :
        libcrypto.RAND_pseudo_bytes(byref(buffer), num)
        return buffer.raw[:num]
    finally :
        _free_buffer(libcrypto, buffer)

def seed(libcrypto, data, entropy=None):
    if type(data) != type(""):
        raise TypeError, "A string is expected"
    ptr = c_char_p(data)
    size = len(data)
    if entropy is None:
        libcrypto.RAND_seed(ptr, size)
    else :
        libcrypto.RAND_add(ptr, size, entropy)

def status(libcrypto):
    return libcrypto.RAND_status()
    
def _free_buffer(libcrypto, buffer):
    libcrypto.RAND_cleanup()
    del(buffer)