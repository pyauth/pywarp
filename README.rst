PyWARP: Python Web Authentication Relying Party library
=======================================================

**PyWARP** is an implementation of the W3C `WebAuthn <https://www.w3.org/TR/webauthn/>`_ standard's Relying Party
component in Python. The WebAuthn standard is used to provide advanced authentication security for two-factor,
multifactor and passwordless authentication models through the use of dedicated hardware security keys and biometric
devices such as `Yubico YubiKey <https://www.yubico.com/>`_,
`Google Titan <https://store.google.com/us/product/titan_security_key_kit>`_,
`TPM <https://en.wikipedia.org/wiki/Trusted_Platform_Module>`_, and
`Touch ID <https://en.wikipedia.org/wiki/Touch_ID>`_. PyWARP's design goal is to provide an
`ergonomic <https://github.com/google/mundane/blob/master/DESIGN.md>`_ and intuitive API to guide the implementer with good
defaults and trusted dependencies.

Compared to earlier two-factor standards like HOTP (`RFC 4226 <https://tools.ietf.org/html/rfc4226>`_) and TOTP
(`RFC 6238 <https://tools.ietf.org/html/rfc6238>`_), the
`FIDO U2F <https://en.wikipedia.org/wiki/Universal_2nd_Factor>`_ profile of WebAuthn uses asymmetric cryptography to
avoid using a shared secret design, which strengthens your authentication solution against server-side attacks. Hardware
U2F also sequesters the client secret in a dedicated single-purpose device, which strengthens your clients against
client-side attacks. And by automating scoping of credentials to relying party IDs (application origin/domain names),
WebAuthn/U2F adds protection against phishing attacks.

PyWARP implements the *Relying Party* component of WebAuthn. A Relying Party is a server-side application that instructs
the browser (user agent) to use WebAuthn APIs to authenticate its users.

To see an example of PyWARP in action, check the ``examples`` directory. Two demos are included: an
`AWS Chalice <https://github.com/aws/chalice>`_ app and a `Flask <https://github.com/pallets/flask>`_ app.

In addition to reading the `WebAuthn standard <https://www.w3.org/TR/webauthn/>`_, we recommend that implementers read
the `OWASP Authentication Cheat Sheet <https://www.owasp.org/index.php/Authentication_Cheat_Sheet>`_ and
`NIST SP 800-63-3: Digital Authentication Guideline <https://pages.nist.gov/800-63-3/>`_ for a high level overview of
authentication best practices.

Installation
------------
::

    pip install pywarp

PyWARP depends on `cryptography <https://github.com/pyca/cryptography>`_, which in turn requires OpenSSL and CFFI. See
the `cryptography installation docs <https://cryptography.io/en/latest/installation/>`_ for more details.

Synopsis
--------

.. code-block:: python

    from pywarp import RelyingPartyManager, Credential
    # Using DynamoDB as an example. See "storage backends" below for other databases.
    from pywarp.backends import DynamoBackend

    rp_id = "myapp.example.com"  # This must match the origin domain of your app, as seen by the browser.
    rp = RelyingPartyManager("PyWARP demo", rp_id=rp_id, credential_storage_backend=DynamoBackend())

    # Get options for navigator.credentials.create() - pass these to your frontend when registering a user
    opts = rp.get_registration_options(email=str)

    # Run the protocol in https://www.w3.org/TR/webauthn/#registering-a-new-credential,
    # then call the credential storage backend to store the credential public key.
    rp.register(attestation_object=bytes, client_data_json=bytes, email=bytes)

    # Get options for navigator.credentials.get() - pass these to your frontend when logging in a user
    opts = rp.get_authentication_options(email=str)

    # Run the protocol in https://www.w3.org/TR/webauthn/#verifying-assertion,
    # calling the credential storage backend to retrieve the credential public key.
    # If no exception is raised, proceed with user login.
    rp.verify(authenticator_data=bytes, client_data_json=bytes, signature=bytes, user_handle=bytes, raw_id=bytes,
              email=bytes)

See `examples/chalice/app.py <https://github.com/pyauth/pywarp/blob/master/examples/chalice/app.py>`_ and
`examples/chalice/chalicelib/index.html <https://github.com/pyauth/pywarp/blob/master/examples/chalice/chalicelib/index.html>`_
(frontend) for a complete example.

Storage backends
----------------

Your application is presumably using an application server like uWSGI, a database backend like MySQL, PostgreSQL or
MongoDB, and maybe a framework like Flask or Django to tie them together. PyWARP makes no assumptions about your
database, schema, or model. Instead, it provides an abstract class (``pywarp.backends.CredentialStorageBackend``)
representing an interface for storing and retrieving WebAuthn credential data for your users.

To deploy PyWARP, declare a subclass of ``CredentialStorageBackend``. In your subclass, implement bindings to your
database, then pass an instance of your subclass to ``pywarp.RelyingPartyManager(credential_storage_backend=...)``:

.. code-block:: python

    from pywarp import RelyingPartyManager, Credential
    from pywarp.backends import CredentialStorageBackend

    class MyDBBackend(CredentialStorageBackend):
        def __init__(self, ...):
            self.database_client = ...

        def get_credential_by_email(self, email):
            user_record = self.database_client.get(email)
            return Credential(credential_id=user_record["cred_id"],
                              credential_public_key=user_record["cred_pub_key"])

        def save_credential_for_user(self, email, credential):
            self.database_client.update(email, {"cred_id": credential.credential_id,
                                                "cred_pub_key": bytes(credential.public_key)})

        def save_challenge_for_user(self, email, challenge, type):
            self.database_client.update(email, {type + "challenge": challenge})

        def get_challenge_for_user(self, email, type):
            user_record = self.database_client.get(email)
            return user_record[type + "challenge"]

    my_rp = RelyingPartyManager(credential_storage_backend=MyDBBackend(...), ...)

Example: Chalice app
--------------------

The Chalice app example (in the ``examples/chalice`` directory) can be deployed as an
`AWS Lambda <https://aws.amazon.com/lambda/>`_ application when used with conventional AWS account credentials
(configured via ``aws configure`` in the `AWS CLI <https://aws.amazon.com/cli/>`_). This example uses
`DynamoDB <https://aws.amazon.com/dynamodb/>`_ as a storage backend.

To deploy this example, run ``make -C examples/chalice`` after configuring your AWS CLI credentials.

See the `API documentation <https://pywarp.readthedocs.io/>`_ for more.

Authors
-------
* Andrey Kislyuk

Links
-----
* `Project home page (GitHub) <https://github.com/pyauth/pywarp>`_
* `Documentation (Read the Docs) <https://pywarp.readthedocs.io/en/latest/>`_
* `Package distribution (PyPI) <https://pypi.python.org/pypi/pywarp>`_
* `Change log <https://github.com/pyauth/pywarp/blob/master/Changes.rst>`_

Bugs
----
Please report bugs, issues, feature requests, etc. on `GitHub <https://github.com/pyauth/pywarp/issues>`_.

License
-------
Licensed under the terms of the `Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>`_.

.. image:: https://img.shields.io/travis/com/pyauth/pywarp.svg
        :target: https://travis-ci.com/pyauth/pywarp
.. image:: https://codecov.io/github/pyauth/pywarp/coverage.svg?branch=master
        :target: https://codecov.io/github/pyauth/pywarp?branch=master
.. image:: https://img.shields.io/pypi/v/pywarp.svg
        :target: https://pypi.python.org/pypi/pywarp
.. image:: https://img.shields.io/pypi/l/pywarp.svg
        :target: https://pypi.python.org/pypi/pywarp
.. image:: https://readthedocs.org/projects/pywarp/badge/?version=latest
        :target: https://pywarp.readthedocs.io/
