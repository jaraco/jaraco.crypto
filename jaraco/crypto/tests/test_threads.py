from concurrent.futures import ThreadPoolExecutor

from . import test_cipher, test_digest


def exercise_crypto():
    test_digest.test_digest()
    test_cipher.test_cipher(["a" * 1000, "d" * 1000])
    # test_evp.test_rand()


def test_threaded_crypto():
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(exercise_crypto) for _ in range(10)]
    # result() re-raises any exception from the worker thread
    for future in futures:
        future.result()


if __name__ == "__main__":
    test_threaded_crypto()
