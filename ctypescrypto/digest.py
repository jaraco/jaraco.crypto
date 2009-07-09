from ctypes import *

DIGEST_ALGORITHMS = ("MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512")

class DigestError(Exception):
    pass

class DigestType:

    def __init__(self, libcrypto, digest_name):
        self.libcrypto = libcrypto
        self.digest_name = digest_name
        self.digest = self.libcrypto.EVP_get_digestbyname(self.digest_name)
        if self.digest == 0:
            raise DigestError, "Unknown digest: %s" % self.digest_name

    def __del__(self):
        pass

class Digest:

    def __init__(self, libcrypto, digest_type):
        self.libcrypto = libcrypto
        self._clean_ctx()
        self.ctx = self.libcrypto.EVP_MD_CTX_create()
        if self.ctx == 0:
            raise DigestError, "Unable to create digest context"
        result = self.libcrypto.EVP_DigestInit_ex(self.ctx, digest_type.digest, None)
        if result == 0:
            self._clean_ctx()
            raise DigestError, "Unable to initialize digest"
        self.digest_type = digest_type

    def __del__(self):
        self._clean_ctx()

    def update(self, data):
        if self.digest_finalized:
            raise DigestError, "No updates allowed"
        if type(data) != type(""):
            raise TypeError, "A string is expected"
        result = self.libcrypto.EVP_DigestUpdate(self.ctx, c_char_p(data), len(data))
        if result != 1:
            raise DigestError, "Unable to update digest"
        
    def digest(self, data=None):
        if self.digest_finalized:
            raise DigestError, "Digest operation is already completed"
        if data is not None:
            self.update(data)
        self.digest_out = create_string_buffer(256)
        length = c_long(0)
        result = self.libcrypto.EVP_DigestFinal_ex(self.ctx, byref(self.digest_out), byref(length))
        if result != 1 :
            raise DigestError, "Unable to finalize digest"
        self.digest_finalized = True
        return self.digest_out.value[:length.value]

    def _clean_ctx(self):
        try:
            if self.ctx is not None:
                self.libcrypto.EVP_MD_CTX_destroy(self.ctx)
                del(self.ctx)
        except AttributeError:
            pass
        self.digest_out = None
        self.digest_finalized = False