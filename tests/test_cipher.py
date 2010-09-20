from ctypescrypto.cipher import CipherType

def test_cipher_type():
	t = CipherType.from_name('AES-256', 'CBC')
