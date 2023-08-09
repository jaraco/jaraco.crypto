import ctypes

from .support import find_library


class Stack(ctypes.Structure):
    _fields_ = [
        ('num', ctypes.c_int),
        ('data', ctypes.POINTER(ctypes.c_char_p)),
        ('sorted', ctypes.c_int),
        ('num_alloc', ctypes.c_int),
        ('comp', ctypes.c_void_p),
    ]


class CRYPTO_EX_DATA(ctypes.Structure):
    _fields_ = [
        ('sk', ctypes.c_void_p),
        ('dummy', ctypes.c_int),
    ]


class BIO(ctypes.Structure):
    _fields_ = [
        ('method', ctypes.c_void_p),
        ('callback', ctypes.c_void_p),
        ('cb_arg', ctypes.c_char_p),
        ('init', ctypes.c_int),
        ('shutdown', ctypes.c_int),
        ('flags', ctypes.c_int),
        ('retry_reason', ctypes.c_int),
        ('num', ctypes.c_int),
        ('ptr', ctypes.c_void_p),
        ('next_bio', ctypes.c_void_p),
        ('prev_bio', ctypes.c_void_p),
        ('references', ctypes.c_int),
        ('num_read', ctypes.c_ulong),
        ('num_write', ctypes.c_ulong),
        ('ex_data', CRYPTO_EX_DATA),
    ]


FILETYPE_PEM = 1
FILETYPE_ASN1 = 2

lib = find_library('libcrypto') or find_library('libssl')
assert lib, "Couldn't find OpenSSL"

lib.BN_bn2hex.restype = ctypes.c_char_p


class X509(ctypes.Structure):
    _fields_ = []  # type: ignore

    def get_serial_number(self):
        asn1_i = lib.X509_get_serialNumber(ctypes.byref(self))
        bignum = lib.ASN1_INTEGER_to_BN(asn1_i, None)
        try:
            hex = lib.BN_bn2hex(bignum)
            result = int(hex, 16)
        finally:
            lib.BN_free(bignum)
        return result


def load_certificate(type, data):
    bio = lib.BIO_new_mem_buf(data, len(data))

    try:
        if type == FILETYPE_PEM:
            cert = lib.PEM_read_bio_X509(bio, None, None, None)
        else:
            raise ValueError("Unsupported type")
    finally:
        lib.BIO_free(bio)
    if not cert:
        raise Exception("Exception loading cert")
    return ctypes.cast(cert, ctypes.POINTER(X509)).contents


if __name__ == '__main__':
    with open('server.pem', 'rb') as certfile:
        cert_data = certfile.read()
    cert = load_certificate(FILETYPE_PEM, cert_data)
    print(cert.get_serial_number())
