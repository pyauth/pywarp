import datetime
import json

import cbor2
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import NameOID


def test_get_registration_options(fake, rp):
    email = fake.email()
    opts = rp.get_registration_options(email=email)

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
            -2: x,
            -3: y,
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

    client_data_json = json.dumps({
        'challenge': opts['challenge'],
        'type': 'webauthn.create',
    }).encode()

    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(client_data_json)
    verification = auth_data + hasher.finalize()

    att_stmt = {
        'alg': -7,
        'sig': key.sign(verification, ec.ECDSA(hashes.SHA256())),
        'x5c': [att_cert.public_bytes(Encoding.DER)],
    }

    attestation_object = cbor2.dumps({
        'attStmt': att_stmt,
        'authData': auth_data,
        'fmt': 'packed',
    })

    rp.register(client_data_json, attestation_object, email)
