import binascii

import py.test
from ctypescrypto import evp, digest

def test_load_valid_digest_type_by_name():
	t = evp.DigestType.from_name('SHA256')

def test_load_invalid_digest_type_by_name():
	# dne is Does Not Exist
	py.test.raises(evp.DigestError, evp.DigestType.from_name, 'sha-dne')

def test_digest():
	digest_type = digest.DigestType.from_name('SHA512')
	sha512 = digest.Digest(digest_type)
	sha512.update("test")
	assert not sha512.finalized
	digest_ = sha512.digest()
	digest_str = binascii.hexlify(digest_)
	assert len(digest_) == 64
	assert digest_str == (
		"ee26b0dd4af7e749aa1a8ee3c10ae992"
		"3f618980772e473f8819a5d4940e0db2"
		"7ac185f8a0e1d5f84f88bc887fd67b14"
		"3732c304cc5fa9ad8e6f57f50028a8ff")

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
	py.test.skip('not ready yet')
	key1 = '11111111111111111111111111111111'
	key2 = '1111111111111111'
	params = 'AES-256', 'CBC', key1, key2
	ce = cipher.Cipher(*params)
	map(ce.update, data_parts)
	data_enc = ce.finish()
	cd = cipher.Cipher(*params)
	assert cd.finish(data_enc) == ''.join(data_parts)

def test_rand():
	py.test.skip('not ready yet')
	ran = rand.bytes(libcrypto, 100)
	assert len(ran) == 100
