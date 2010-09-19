import ctypes
import os

def find_library(lib_name):
	"""
	Given a name like libeay32, find the best match.
	"""
	# todo, allow the target environment to customize this behavior
	lib_name = r'c:\Program Files\OpenSSL\%(lib_name)s.dll' % vars()
	assert os.path.exists(lib_name)
	return ctypes.cdll.LoadLibrary(lib_name)