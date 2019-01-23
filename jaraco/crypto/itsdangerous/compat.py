import datetime
import time

import itsdangerous


class EpochOffsetSigner(itsdangerous.TimestampSigner):
    EPOCH = datetime.datetime(2011, 1, 1).timestamp()

    def get_timestamp(self):
        return int(time.time() - self.EPOCH)


def unsign(signer, blob, **kwargs):
    try:
        return signer.unsign(blob, **kwargs)
    except itsdangerous.exc.SignatureExpired:
        compat_signer = EpochOffsetSigner(signer.secret_key)
        return compat_signer.unsign(blob, **kwargs)
