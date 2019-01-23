import datetime
import time
import sys

import itsdangerous
from backports.datetime_timestamp import timestamp


class EpochOffsetSigner(itsdangerous.TimestampSigner):
    EPOCH = timestamp(datetime.datetime(2011, 1, 1))

    def get_timestamp(self):
        return int(time.time() - self.EPOCH)


def unsign(signer, blob, **kwargs):
    """
    >>> from freezegun import freeze_time
    >>> frozen = freeze_time('2019-01-23T18:45Z')

    This signed value was signed by itsdangerous 0.24
    >>> signed = 'my string.DypHqg.FowpFfFG-kYA7P-qujGwVt9oJCo'
    >>> signer = itsdangerous.TimestampSigner(b'secret-key')
    >>> _, orig_ts = signer.unsign(signed, return_timestamp=True)
    >>> orig_ts
    datetime.datetime(1978, 1, 23, 18, 44, 58)

    This is where the expectation fails using a late itsdangerous.
    >>> frozen(signer.unsign)(signed, max_age=5)
    Traceback (most recent call last):
    ...
    itsdangerous.exc.SignatureExpired: Signature age 1293840002 > 5 seconds
    >>> res, ts = frozen(unsign)(
    ...     signer, signed, max_age=5, return_timestamp=True)
    >>> res
    b'my string'
    >>> ts == orig_ts
    True
    """
    try:
        return signer.unsign(blob, **kwargs)
    except itsdangerous.exc.SignatureExpired:
        compat_signer = EpochOffsetSigner(signer.secret_key)
        return compat_signer.unsign(blob, **kwargs)


if sys.version_info < (3,):
    unsign.__doc__ = unsign.__doc__.replace('itsdangerous.exc.', '')
