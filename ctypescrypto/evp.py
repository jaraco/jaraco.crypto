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

class DigestContext(Structure):
	_fields_ = [
		('digest', POINTER(DigestType)),
		('engine', c_void_p), # todo, POINTER(ENGINE)
		('flags', c_ulong),
		('md_data', c_void_p),
		('pctx', c_void_p), # todo, POINTER(EVP_PKEY_CTX)
		('update', c_void_p),
		]

	@staticmethod
	def create():
		res = lib.EVP_MD_CTX_create()
		if not res:
			raise DigestError("Unable to create digest context")
		return res

	def destroy(self):
		lib.EVP_MD_CTX_destroy(self)

	def __del__(self):
		self.destroy()

class Digest(object):
	finalized = False
	def __init__(self, digest_type):
		self.digest_type = digest_type
		self.context = DigestContext.create()
		result = lib.EVP_DigestInit_ex(self.context, digest_type, None)
		if result == 0:
			raise DigestError("Unable to initialize digest")

	def update(self, data):
		if self.finalized:
			raise DigestError("Digest is finalized; no updates allowed")
		if not isinstance(data, basestring):
			raise TypeError("A string is expected")
		result = lib.EVP_DigestUpdate(self.context, data, len(data))
		if result != 1:
			raise DigestError, "Unable to update digest"
		
	def digest(self, data=None):
		if self.digest_finalized:
			raise DigestError, "Digest operation is already completed"
		if data is not None:
			self.update(data)
		self.digest_out = create_string_buffer(256)
		length = c_long(0)
		result = self.libcrypto.EVP_DigestFinal_ex(self.ctx, byref(self.digest_out), byref(length))
		if result != 1 :
			raise DigestError, "Unable to finalize digest"
		self.digest_finalized = True
		return self.digest_out.raw[:length.value]

lib = find_library('libeay32')
lib.EVP_get_digestbyname.argtypes = c_char_p,
lib.EVP_get_digestbyname.restype = POINTER(DigestType)
lib.OpenSSL_add_all_digests()
lib.OpenSSL_add_all_ciphers()
