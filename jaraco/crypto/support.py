import ctypes
import os
import platform

from six.moves import filter


def find_library(lib_name):
	"""
	Given a name like libeay32, find the best match.
	"""
	# todo, allow the target environment to customize this behavior
	roots = [
		'c:\\Program Files\\OpenSSL\\',
		'\\OpenSSL-Win64',
		'/usr/local/opt/openssl/lib/',
		'/lib/x86_64-linux-gnu/',
	]
	ext = (
		'.dll' if platform.system() == 'Windows' else
		'.dylib' if platform.system() == 'Darwin' else
		'.so.1.0.0' if platform.system() == 'Linux' else
		'.so'
	)
	filename = lib_name + ext
	found = next(_find_file(filename, roots), None)
	return found and ctypes.cdll.LoadLibrary(found)


def _find_file(filename, roots):
	candidates = (
		os.path.join(root, filename)
		for root in roots
	)
	return filter(os.path.exists, candidates)
