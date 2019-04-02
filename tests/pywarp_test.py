import datetime
import json

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import NameOID

from ..pywarp.utils import b64decode, b64encode


def test_get_registration_options(fake, rp):
    email = fake.email()
    opts = rp.get_registration_options(email=email)

    challenge = rp.backend.get_challenge(email, 'registration')
    assert b64decode(opts['challenge']) == challenge

    user = opts['user']
    assert user['name'] == email

    display_name = fake.name()
    icon = fake.image_url()
    opts = rp.get_registration_options(
        email=email, display_name=display_name, icon=icon
    )

    user = opts['user']
    assert user['name'] == email
    assert user['displayName'] == display_name
    assert user['icon'] == icon


def test_register_packed_basic(fake, rp):
    email = fake.email()
    opts = rp.get_registration_options(email=email)

    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = key.public_key()
    public_numbers = public_key.public_numbers()
    x, y = public_numbers.x, public_numbers.y

    aaguid = bytes(x % 8 + 1 for x in range(16))
    credential_id = bytes(x % 8 + 1 for x in range(16))
    length = len(credential_id)
    attested_data = b''.join([
        aaguid,  # aaguid
        length.to_bytes(2, 'big'),  # credentialIdLength
        credential_id,  # credentialId
        cbor2.dumps({
            1: 2,  # EC2 key type
            3: -7,  # ES256 signature algorithm
            -1: 1,  # P-256 curve
            -2: x.to_bytes((x.bit_length() + 7) // 8, 'big'),
            -3: y.to_bytes((y.bit_length() + 7) // 8, 'big'),
        }),
    ])

    auth_data = b''.join([
        bytes(x % 8 for x in range(32)),
        (0b1000001).to_bytes(1, 'big'),
        bytes(4),
        attested_data,
    ])

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'ACME Corporation'),
        x509.NameAttribute(
            NameOID.ORGANIZATIONAL_UNIT_NAME, 'Authenticator Attestation'
        ),
        x509.NameAttribute(NameOID.COMMON_NAME, 'PyWARP'),
    ])

    now = datetime.datetime.utcnow()
    att_cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(public_key) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(now) \
        .not_valid_after(now + datetime.timedelta(days=1)) \
        .sign(key, hashes.SHA256(), default_backend())

    client_data_json = b64encode(json.dumps({
        'challenge': opts['challenge'],
        'type': 'webauthn.create',
    }))

    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(client_data_json.encode())
    verification = auth_data + hasher.finalize()

    att_stmt = {
        'alg': -7,
        'sig': key.sign(verification, ec.ECDSA(hashes.SHA256())),
        'x5c': [att_cert.public_bytes(Encoding.DER)],
    }

    attestation_object = b64encode(cbor2.dumps({
        'attStmt': att_stmt,
        'authData': auth_data,
        'fmt': 'packed',
    }))

    rp.register(client_data_json, attestation_object, email)


@pytest.mark.skip(reason="can't test this without mocking fido validation")
def test_register_fido_u2f(rp):
    email = 'rsa@pm.me'
    challenge = b64decode('jXEy68weYcMGRsvvV6T3WFDBL1qPH3KMCpS67D3vCQE=')
    rp.backend.save_challenge(email, challenge, 'registration')
    # opts = rp.get_registration_options(email=email)

    client_data_json = b'eyJjaGFsbGVuZ2UiOiJqWEV5Njh3ZVljTUdSc3Z2VjZUM1dGREJ' \
                       b'MMXFQSDNLTUNwUzY3RDN2Q1FFIiwiY2xpZW50RXh0ZW5zaW9ucy' \
                       b'I6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luI' \
                       b'joiaHR0cDovL2xvY2FsaG9zdDoxMjM0IiwidHlwZSI6IndlYmF1' \
                       b'dGhuLmNyZWF0ZSJ9'
    attestation_object = b'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhAPxNe' \
                         b'UCgZ5DXZI/0y1n+1A5FfgXHc3ALN9MYxeCs6SCGAiEA/Qb1eK' \
                         b'mT898dZUY4YIHkXwOZs+gNySJ9w505mLCyH7xjeDVjgVj+MIH' \
                         b'7MIHhoAMCAQICAQAwCgYIKoZIzj0EAwIwHDEaMBgGA1UEAwwR' \
                         b'Tm8gU3VjaCBBdXRob3JpdHkwHhcNMTYwMTAxMDAwMDAwWhcNM' \
                         b'zYwMTAxMDAwMDAwWjAyMTAwLgYDVQQDDCdUaGlzIFUyRiBEZX' \
                         b'ZpY2UgRG9lcyBOb3QgRG8gQXR0ZXN0YXRpb24wWTATBgcqhkj' \
                         b'OPQIBBggqhkjOPQMBBwNCAASVylYdcurkg+1xE1fjpGdyxZ0Q' \
                         b'QVZ4fq3GAd59yvuh1IL7pyIvR8HYlq3SwY5qcPzra1lamkQZX' \
                         b'bUVJ0v1kT4BMAoGCCqGSM49BAMCAwkAMAYCAQMCAQFoYXV0aE' \
                         b'RhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZd' \
                         b'jQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEA8V41AW45S1010MFd8' \
                         b'flin4iESSfpcEcWlGHkPWbKas5ZyZ+oYYlNJKUlj1sVuGeZeY' \
                         b'Brn4C1ogY2eXJxhnUeJpQECAyYgASFYIJXKVh1y6uSD7XETV+' \
                         b'OkZ3LFnRBBVnh+rcYB3n3K+6HUIlgggvunIi9HwdiWrdLBjmp' \
                         b'w/OtrWVqaRBldtRUnS/WRPgE='

    rp.register(
        b64decode(client_data_json).decode(),
        b64decode(attestation_object),
        email,
    )
