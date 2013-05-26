import itertools

from jaraco.crypto import cipher

def test_cipher_type(algorithm, mode):
	# One can pass the algorithm and mode separately or together
	t = cipher.CipherType.from_name(algorithm, mode)
	t = cipher.CipherType.from_name(algorithm + '-' + mode)

def pytest_generate_tests(metafunc):
	if "data_parts" in metafunc.funcargnames:
		for i in range(0, 1000, 50):
			metafunc.addcall(funcargs=dict(
				data_parts=('a'*i, 'b'*i, 'c'*i)
				))
	if metafunc.funcargnames == ['algorithm', 'mode']:
		pairs = itertools.product(cipher.CIPHER_ALGORITHMS,
			cipher.CIPHER_MODES)
		for algorithm, mode in pairs:
			# apparently DES-EDE3-ECB is not a valid mode
			if (algorithm, mode) == ('DES-EDE3', 'ECB'): continue
			metafunc.addcall(funcargs=dict(
				algorithm=algorithm, mode=mode
				))

def test_cipher(data_parts):
	"""
	Encrypt and decrypt the data_parts supplied and ensure the source
	matches the result.
	"""
	key = '11111111111111111111111111111111'
	iv = '1111111111111111'
	params = ('AES-256', 'CBC'), key, iv
	ce = cipher.Cipher(*params)
	map(ce.update, data_parts)
	data_enc = ce.finalize()
	cd = cipher.Cipher(*params, encrypt=False)
	assert cd.finalize(data_enc) == ''.join(data_parts)

