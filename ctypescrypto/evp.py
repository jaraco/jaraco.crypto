from ctypes import *

from .support import find_library

MAX_MD_SIZE = 64

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
	c_name = 'EVP_MD_CTX'
	_fields_ = [
		('digest', POINTER(DigestType)),
		('engine', c_void_p), # todo, POINTER(ENGINE)
		('flags', c_ulong),
		('md_data', c_void_p),
		('pctx', c_void_p), # todo, POINTER(EVP_PKEY_CTX)
		('update', c_void_p),
		]

	def __init__(self):
		lib.EVP_MD_CTX_init(self)

class Digest(object):
	finalized = False
	def __init__(self, digest_type):
		self.digest_type = digest_type
		self.context = DigestContext()
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
		if data is not None:
			self.update(data)
		result_buffer = create_string_buffer(MAX_MD_SIZE)
		result_length = c_uint()
		res_code = lib.EVP_DigestFinal_ex(self.context, result_buffer,
			result_length)
		if res_code != 1 :
			raise DigestError, "Unable to finalize digest"
		self.finalized = True
		result = result_buffer.raw[:result_length.value]
		# override self.digest to return the same result on subsequent
		#  calls
		self.digest = lambda: result
		return result

lib = find_library('libeay32')
## Define the argtypes and result types for the EVP functions
lib.EVP_get_digestbyname.argtypes = c_char_p,
lib.EVP_get_digestbyname.restype = POINTER(DigestType)
lib.EVP_DigestInit.argtypes = (
	POINTER(DigestContext), POINTER(DigestType),
	)
lib.EVP_DigestInit_ex.argtypes = lib.EVP_DigestInit.argtypes + (c_void_p,)
lib.EVP_DigestInit_ex.restype = c_int
lib.EVP_MD_CTX_init.argtypes = POINTER(DigestContext),
lib.EVP_MD_CTX_create.restype = POINTER(DigestContext)
lib.EVP_DigestUpdate.argtypes = POINTER(DigestContext), c_char_p, c_int
lib.EVP_DigestUpdate.restype = c_int
lib.EVP_DigestFinal_ex.argtypes = (POINTER(DigestContext),
	c_char_p, POINTER(c_uint),
	)
lib.EVP_DigestFinal_ex.restype = c_int

## Initialize the engines
lib.OpenSSL_add_all_digests()
lib.OpenSSL_add_all_ciphers()
