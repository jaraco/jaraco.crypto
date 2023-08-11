import platform


non_windows = platform.system() != 'Windows'


collect_ignore = (
    []
    + [
        'jaraco/crypto/cert.py',
    ]
    * non_windows
)
