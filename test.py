import os
from ctypes import *
#Use find_libary if dll in path
#from ctypes.util import find_library
#Location of Cryptographic DLL
from ctypes.util import find_library
crypto_dll = find_library('libeay32')
crypto_dll = r'c:\program files\openssl\libeay32.dll'
libcrypto = cdll.LoadLibrary(crypto_dll)
libcrypto.OpenSSL_add_all_digests()
libcrypto.OpenSSL_add_all_ciphers()

from threading import Thread
from ctypescrypto import digest, cipher, rand
import binascii

def test_basic_functionality():
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

class ThreadedTester(Thread):
	failed = False
	def run(self):
		try:
			test_basic_functionality()
		except Exception, e:
			self.failed = True
			self.exception = e

def test_threaded_crypto():
	threads = [ThreadedTester() for i in range(10)]
	map(lambda t: t.start(), threads)
	# wait for the threads to complete
	map(lambda t: t.join(), threads)
	assert all(not t.failed for t in threads), "Some threads failed"

if __name__ == '__main__':
	test_basic_functionality()
	test_threaded_crypto()
