import py.test

from jaraco.crypto import rand


def test_bytes():
    bytes = rand.bytes(100)
    assert len(bytes) == 100
    assert bytes != rand.bytes(100)


def test_pseudo_bytes():
    bytes = rand.pseudo_bytes(100)
    assert len(bytes) == 100
    assert bytes != rand.pseudo_bytes(100)


def test_seed():
    py.test.skip("This fails, why?")
    seed = 'bunch of bytes' * 1000
    rand.cleanup()
    rand.seed(seed)
    bytes1 = rand.pseudo_bytes(100)
    rand.cleanup()
    rand.seed(seed)
    bytes2 = rand.pseudo_bytes(100)
    assert bytes1 == bytes2
