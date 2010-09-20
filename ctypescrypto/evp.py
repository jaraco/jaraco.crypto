import itertools
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

get_cipherbyname = lib.EVP_get_cipherbyname
get_cipherbyname.argtypes = c_char_p,

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
	('cipher', c_void_p), # POINTER(CipherType)
	('engine', c_void_p), # POINTER(ENGINE)
	('encrypt', c_int),
	('buf_len', c_int),
	('oiv', c_char*MAX_IV_LENGTH),
	('iv', c_char*MAX_IV_LENGTH),
	('buf', c_char*MAX_BLOCK_LENGTH),
	('num', c_int),
	('app_data', c_void_p),
	('key_len', c_int),
	('flags', c_ulong),
	('cipher_data', c_void_p),
	('final_used', c_int),
	('block_mask', c_int),
	('final', c_char*MAX_BLOCK_LENGTH),
]

#EncryptInit_ex = lib.EVP_EncryptInit_ex
#DecryptInit_ex = lib.EVP_DecryptInit_ex
#...
for ed, method in itertools.product(
	['Encrypt', 'Decrypt', 'Cipher'],
	['Init_ex', 'Update', 'Final_ex'],
	):
	local_name = ''.join([ed, method])
	lib_name = ''.join(['EVP_', ed, method])
	func = getattr(lib, lib_name)
	func.restype = c_int
	globals()[local_name] = func

## Initialize the engines
lib.OpenSSL_add_all_digests()
lib.OpenSSL_add_all_ciphers()
