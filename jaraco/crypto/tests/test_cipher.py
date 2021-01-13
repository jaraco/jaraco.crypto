import itertools

import pytest

from jaraco.crypto import cipher


def algorithm_modes():
    pairs = itertools.product(cipher.CIPHER_ALGORITHMS, cipher.CIPHER_MODES)
    for algorithm, mode in pairs:
        # apparently DES-EDE3-ECB is not a valid mode
        if (algorithm, mode) == ('DES-EDE3', 'ECB'):
            continue
        yield algorithm, mode


@pytest.mark.parametrize(['algorithm', 'mode'], algorithm_modes())
def test_cipher_type(algorithm, mode):
    # One can pass the algorithm and mode separately or together
    cipher.CipherType.from_name(algorithm, mode)
    cipher.CipherType.from_name(algorithm + '-' + mode)


@pytest.mark.parametrize(
    'data_parts', [('a' * i, 'b' * i, 'c' * i) for i in range(0, 1000, 50)]
)
def test_cipher(data_parts):
    """
    Encrypt and decrypt the data_parts supplied and ensure the source
    matches the result.
    """
    key = '11111111111111111111111111111111'
    iv = '1111111111111111'
    params = ('AES-256', 'CBC'), key, iv
    ce = cipher.Cipher(*params)
    list(map(ce.update, data_parts))
    data_enc = ce.finalize()
    cd = cipher.Cipher(*params, encrypt=False)
    assert cd.finalize(data_enc) == ''.join(data_parts).encode()
