from ctypescrypto import cipher

def test_cipher_type():
	t = cipher.CipherType.from_name('AES-256', 'CBC')

def pytest_generate_tests(metafunc):
	if "data_parts" in metafunc.funcargnames:
		for i in range(0, 1000, 50):
			metafunc.addcall(funcargs=dict(
				data_parts=('a'*i, 'b'*i, 'c'*i)
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
	data_enc = ce.finish()
	cd = cipher.Cipher(*params, encrypt=False)
	assert cd.finish(data_enc) == ''.join(data_parts)

