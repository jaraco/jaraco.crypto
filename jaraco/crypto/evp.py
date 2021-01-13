import itertools
from ctypes import (
    c_int,
    c_ulong,
    c_void_p,
    c_char_p,
    POINTER,
    c_uint,
    c_char,
)

from .support import find_library


get_digestbyname = None
DigestInit = None
DigestInit_ex = None
DigestUpdate = None
DigestFinal_ex = None
get_cipherbyname = None

MAX_MD_SIZE = 64

_digest_type_fields = [
    ('type', c_int),
    ('pkey_type', c_int),
    ('md_size', c_int),
    ('flags', c_ulong),
    ('init', c_void_p),
    ('update', c_void_p),
    ('final', c_void_p),
    ('copy', c_void_p),
    ('cleanup', c_void_p),
    ('sign', c_void_p),
    ('verify', c_void_p),
    ('required_pkey_type', c_int * 5),
    ('block size', c_int),
    ('ctx_size', c_int),
    ('md_ctrl', c_void_p),
]

_digest_context_fields = [
    ('p_type', c_void_p),  # POINTER(DigestType)
    ('engine', c_void_p),  # todo, POINTER(ENGINE)
    ('flags', c_ulong),
    ('md_data', c_void_p),
    ('pctx', c_void_p),  # todo, POINTER(EVP_PKEY_CTX)
    ('update_func', c_void_p),
]


def _reg(name):
    """
    Copy the function by the given name from the EVP library into this
    namespace.
    """
    libname = 'EVP_' + name
    globals()[name] = getattr(lib, libname)


lib = find_library('libeay32') or find_library('libssl')
assert lib, "Couldn't find OpenSSL"

# Define the argtypes and result types for the EVP functions
list(
    map(
        _reg,
        'get_digestbyname DigestInit DigestInit_ex '
        'DigestUpdate DigestFinal_ex'.split(),
    )
)


def _set_digest_arg_types(DigestType, Digest):
    get_digestbyname.argtypes = (c_char_p,)
    get_digestbyname.restype = POINTER(DigestType)
    DigestInit.argtypes = (
        POINTER(Digest),
        POINTER(DigestType),
    )
    DigestInit_ex.argtypes = lib.EVP_DigestInit.argtypes + (c_void_p,)
    DigestInit_ex.restype = c_int
    DigestUpdate.argtypes = POINTER(Digest), c_char_p, c_int
    DigestUpdate.restype = c_int
    DigestFinal_ex.argtypes = (
        POINTER(Digest),
        c_char_p,
        POINTER(c_uint),
    )
    DigestFinal_ex.restype = c_int


_reg('get_cipherbyname')
get_cipherbyname.argtypes = (c_char_p,)  # type: ignore

_cipher_fields = [
    ('nid', c_int),
    ('block_size', c_int),
    ('key_len', c_int),
    ('iv_len', c_int),
    ('flags', c_ulong),
    ('init', c_void_p),
    ('do_cipher', c_void_p),
    ('cleanup', c_void_p),
    ('ctx_size', c_int),
    ('set_asn1_parameters', c_void_p),
    ('get_asn1_parameters', c_void_p),
    ('ctrl', c_void_p),
    ('app_data', c_void_p),
]

MAX_IV_LENGTH = 16
MAX_BLOCK_LENGTH = 32
MAX_KEY_LENGTH = 32

_cipher_context_fields = [
    ('cipher', c_void_p),  # POINTER(CipherType)
    ('engine', c_void_p),  # POINTER(ENGINE)
    ('encrypt', c_int),
    ('buf_len', c_int),
    ('oiv', c_char * MAX_IV_LENGTH),
    ('iv', c_char * MAX_IV_LENGTH),
    ('buf', c_char * MAX_BLOCK_LENGTH),
    ('num', c_int),
    ('app_data', c_void_p),
    ('key_len', c_int),
    ('flags', c_ulong),
    ('cipher_data', c_void_p),
    ('final_used', c_int),
    ('block_mask', c_int),
    ('final', c_char * MAX_BLOCK_LENGTH),
]

# EncryptInit_ex = lib.EVP_EncryptInit_ex
# DecryptInit_ex = lib.EVP_DecryptInit_ex
# ...
for ed, method in itertools.product(
    ['Encrypt', 'Decrypt', 'Cipher'],
    ['Init_ex', 'Update', 'Final_ex'],
):
    local_name = ''.join([ed, method])
    lib_name = ''.join(['EVP_', ed, method])
    func = getattr(lib, lib_name)
    func.restype = c_int
    globals()[local_name] = func
