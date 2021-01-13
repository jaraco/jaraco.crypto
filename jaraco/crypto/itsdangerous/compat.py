"""
Compatibility shim for timestamp compatibility between
itsdangerous 0.24 and 1.x. See `itsdangerous 120
<https://github.com/pallets/itsdangerous/issues/120>`_
for motivation and details.
"""

import time
import sys
import datetime

import itsdangerous


class EpochOffsetSigner(itsdangerous.TimestampSigner):
    """
    >>> EpochOffsetSigner.EPOCH
    1293840000.0
    """

    try:
        EPOCH = datetime.datetime(2011, 1, 1, tzinfo=datetime.timezone.utc).timestamp()
    except AttributeError:
        EPOCH = 1293840000.0

    def get_timestamp(self):
        return int(time.time() - self.EPOCH)

    def timestamp_to_datetime(self, ts):
        return super(EpochOffsetSigner, self).timestamp_to_datetime(ts + self.EPOCH)


def unsign(signer, blob, **kwargs):
    """
    Prepare to freeze time; create frozen decorator

    >>> from freezegun import freeze_time
    >>> frozen = freeze_time('2019-01-23T18:45')

    This signed value was signed by itsdangerous 0.24 at
    2019-01-23 18:44:58 UTC

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

    But if you call this compatibility wrapper instead, you get the
    desired result.

    >>> res, ts = frozen(unsign)(
    ...     signer, signed, max_age=5, return_timestamp=True)
    >>> res
    b'my string'
    >>> ts
    FakeDatetime(2019, 1, 23, 18, 44, 58)

    And the signature does show as expired when it's supposed to be.

    >>> freeze_time('2019-01-23T18:45:58')(unsign)(signer, signed, max_age=5)
    Traceback (most recent call last):
    ...
    itsdangerous.exc.SignatureExpired: Signature age 60 > 5 seconds
    """
    try:
        return signer.unsign(blob, **kwargs)
    except itsdangerous.exc.SignatureExpired:
        compat_signer = EpochOffsetSigner(None)
        vars(compat_signer).update(vars(signer))
        return compat_signer.unsign(blob, **kwargs)


if sys.version_info < (3,):
    unsign.__doc__ = unsign.__doc__.replace('itsdangerous.exc.', '')
