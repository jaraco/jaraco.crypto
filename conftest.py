import platform


non_windows = platform.system() != 'Windows'


collect_ignore = [
    'certutil.py',
] + [
    'jaraco/crypto/cert.py',
] * non_windows
