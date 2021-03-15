v3.0.1
======

Rely on PEP 420 for namespace package.

v3.0.0
======

Updated to run against OpenSSL 1.1.

2.1
===

Added ``jaraco.crypto.itsdangerous.compat`` module, providing
the `compatibility shim presented in pallets/itsdangerous 120
<https://github.com/pallets/itsdangerous/issues/120#issuecomment-456913331>`_.

2.0
===

Switch to `pkgutil namespace technique
<https://packaging.python.org/guides/packaging-namespace-packages/#pkgutil-style-namespace-packages>`_
for the ``jaraco`` namespace.

1.1.1
=====

Minor package cleanup. Run tests on appveyor.

1.1
===

Refreshed packaging. Tests now run on some non-Windows environments.

Initial Python 3 support.

Blowfish module is deprecated on Python 3. Use `blowfish
<https://pypi.org/project/blowfish>`_ instead.

1.0
===

Initial release
