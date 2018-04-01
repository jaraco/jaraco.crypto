import platform

collect_ignore = [
	'certutil.py',
]


if platform.system() != 'Windows':
	collect_ignore.extend([
		'jaraco/crypto/cert.py',
	])
