import os
from ctypes import *
#Use find_libary if dll in path
#from ctypes.util import find_library
#Location of Cryptographic DLL
crypto_dll = os.path.join(r'C:\Python24', 'libeay32.dll')
libcrypto = cdll.LoadLibrary(crypto_dll)
libcrypto.OpenSSL_add_all_digests()
libcrypto.OpenSSL_add_all_ciphers()

from threading import Thread
from ctypescrypto import digest, cipher, rand
import binascii

class TestThread(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        test_func()

def test_func():
    digest_type = digest.DigestType(libcrypto, 'SHA512')
    sha512 = digest.Digest(libcrypto, digest_type)
    sha512.update("test")
    assert binascii.hexlify(sha512.digest()) == "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f5"
    for i in xrange(1, 1000):
        c = cipher.CipherType(libcrypto, 'AES-256', 'CBC')
        ce = cipher.Cipher(libcrypto, c, '11111111111111111111111111111111', '1111111111111111', encrypt=True)
        ce.update("a" * i)
        ce.update("b" * i)
        e_t = ce.finish('c' * i)
        c = cipher.CipherType(libcrypto, 'AES-256', 'CBC')
        cd = cipher.Cipher(libcrypto, c, '11111111111111111111111111111111', '1111111111111111', encrypt=False)
        assert cd.finish(e_t)==("a" * i) + ("b" * i) + ("c" * i)
    ran = rand.bytes(libcrypto, 100)
    assert len(ran) == 100

for i in xrange(1, 10):
    th = TestThread()
    th.start()