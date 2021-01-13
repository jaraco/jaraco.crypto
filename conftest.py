import platform

import six


collect_ignore = [
    'certutil.py',
]


if platform.system() != 'Windows':
    collect_ignore.extend(
        [
            'jaraco/crypto/cert.py',
        ]
    )


if six.PY3:
    collect_ignore.extend(
        [
            'jaraco/crypto/blowfish.py',
        ]
    )
