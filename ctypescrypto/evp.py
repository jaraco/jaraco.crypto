from ctypes import *

from .support import find_library

class DigestError(Exception): pass

class DigestType(Structure):
	_fields_ = [
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
		('required_pkey_type', c_int*5),
		('block size', c_int),
		('ctx_size', c_int),
		('md_ctrl', c_void_p),
	]

	@classmethod
	def from_name(cls, digest_name):
		res = lib.EVP_get_digestbyname(digest_name)
		if not res:
			raise DigestError("Unknown Digest: %(digest_name)s" % vars())
		return res.contents

lib = find_library('libeay32')
lib.EVP_get_digestbyname.argtypes = c_char_p,
lib.EVP_get_digestbyname.restype = POINTER(DigestType)
lib.OpenSSL_add_all_digests()
lib.OpenSSL_add_all_ciphers()
