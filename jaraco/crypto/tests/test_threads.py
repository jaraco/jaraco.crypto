from threading import Thread

from . import test_cipher
from . import test_digest


class ThreadedTester(Thread):
    failed = False

    def run(self):
        try:
            test_digest.test_digest()
            test_cipher.test_cipher(['a' * 1000, 'd' * 1000])
            # test_evp.test_rand()
        except Exception as e:
            self.failed = True
            self.exception = e


def test_threaded_crypto():
    threads = [ThreadedTester() for i in range(10)]
    map(lambda t: t.start(), threads)
    # wait for the threads to complete
    map(lambda t: t.join(), threads)
    assert all(not t.failed for t in threads), "Some threads failed"


if __name__ == '__main__':
    test_threaded_crypto()
