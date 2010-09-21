import py.test
from ctypescrypto import evp, digest

def test_rand():
	py.test.skip('not ready yet')
	ran = rand.bytes(libcrypto, 100)
	assert len(ran) == 100
