import ctypes

import six

from . import evp


class DigestError(Exception):
    pass


class DigestType(ctypes.Structure):
    _fields_ = evp._digest_type_fields

    @classmethod
    def from_name(cls, digest_name):
        res = evp.get_digestbyname(digest_name.encode('ascii'))
        if not res:
            raise DigestError("Unknown Digest: %(digest_name)s" % vars())
        return res.contents


class Digest(ctypes.Structure):
    _fields_ = evp._digest_context_fields
    finalized = False

    def __init__(self, digest_type):
        self.digest_type = digest_type
        result = evp.DigestInit_ex(self, digest_type, None)
        if result == 0:
            raise DigestError("Unable to initialize digest")

    def update(self, data):
        if self.finalized:
            raise DigestError("Digest is finalized; no updates allowed")
        if isinstance(data, six.text_type):
            data = data.encode()
        result = evp.DigestUpdate(self, data, len(data))
        if result != 1:
            raise DigestError("Unable to update digest")

    def digest(self, data=None):
        if data is not None:
            self.update(data)
        result_buffer = ctypes.create_string_buffer(evp.MAX_MD_SIZE)
        result_length = ctypes.c_uint()
        res_code = evp.DigestFinal_ex(self, result_buffer, result_length)
        if res_code != 1:
            raise DigestError("Unable to finalize digest")
        self.finalized = True
        result = result_buffer.raw[: result_length.value]
        # override self.digest to return the same result on subsequent
        #  calls
        self.digest = lambda: result
        return result


evp._set_digest_arg_types(DigestType, Digest)
