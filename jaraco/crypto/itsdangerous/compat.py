import datetime
import time

import itsdangerous
from backports.datetime_timestamp import timestamp


class EpochOffsetSigner(itsdangerous.TimestampSigner):
    EPOCH = timestamp(datetime.datetime(2011, 1, 1))

    def get_timestamp(self):
        return int(time.time() - self.EPOCH)


def unsign(signer, blob, **kwargs):
    """
    >>> from freezegun import freeze_time
    >>> frozen = freeze_time('2019-01-23T18:52:55Z')

    This signed value was signed by itsdangerous 0.24
    >>> signed = 'my string.DypHqg.FowpFfFG-kYA7P-qujGwVt9oJCo'
    >>> signer = itsdangerous.TimestampSigner(b'secret-key')
    >>> frozen(unsign)(signer, signed, max_age=5)
    b'my string'
    """
    try:
        return signer.unsign(blob, **kwargs)
    except itsdangerous.exc.SignatureExpired:
        compat_signer = EpochOffsetSigner(signer.secret_key)
        return compat_signer.unsign(blob, **kwargs)
