import py.test
from ctypescrypto import evp

def test_load_valid_digest_type_by_name():
	t = evp.DigestType.from_name('SHA256')

def test_load_invalid_digest_type_by_name():
	# dne is Does Not Exist
	py.test.raises(evp.DigestError, evp.DigestType.from_name, 'sha-dne')