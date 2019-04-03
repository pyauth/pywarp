import json

import cbor2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

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


def test_register_packed_basic(
    att_cert, attested_data, fake, private_key, public_key, rp,
):
    email = fake.email()
    opts = rp.get_registration_options(email=email)

    auth_data = b''.join([
        bytes(x % 8 for x in range(32)),
        (0b1000001).to_bytes(1, 'big'),
        bytes(4),
        attested_data,
    ])

    client_data_json = json.dumps({
        'challenge': opts['challenge'],
        'type': 'webauthn.create',
    })

    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(client_data_json.encode())
    verification = auth_data + hasher.finalize()

    att_stmt = {
        'alg': -7,
        'sig': private_key.sign(verification, ec.ECDSA(hashes.SHA256())),
        'x5c': [att_cert.public_bytes(Encoding.DER)],
    }

    attestation_object = b64encode(cbor2.dumps({
        'attStmt': att_stmt,
        'authData': auth_data,
        'fmt': 'packed',
    }))

    rp.register(b64encode(client_data_json), attestation_object, email)


def test_register_fido_u2f(
    att_cert, attested_data, credential_id, fake, public_numbers, private_key,
    rp,
):
    email = fake.email()
    opts = rp.get_registration_options(email=email)

    auth_data = b''.join([
        bytes(x % 8 for x in range(32)),
        (0b1000001).to_bytes(1, 'big'),
        b'\x00\x00\x00\x00',
        attested_data,
    ])

    client_data_json = json.dumps({
        'challenge': opts['challenge'],
        'type': 'webauthn.create',
    })

    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(client_data_json.encode())
    client_data_hash = hasher.finalize()

    public_key_u2f = b''.join([
        b'\x04',
        public_numbers.x.to_bytes(32, 'big'),
        public_numbers.y.to_bytes(32, 'big')
    ])

    verification = b''.join([
        b'\x00',
        bytes(x % 8 for x in range(32)),
        client_data_hash,
        credential_id,
        public_key_u2f,
    ])

    att_stmt = {
        'sig': private_key.sign(verification, ec.ECDSA(hashes.SHA256())),
        'x5c': [att_cert.public_bytes(Encoding.DER)],
    }

    attestation_object = b64encode(cbor2.dumps({
        'attStmt': att_stmt,
        'authData': auth_data,
        'fmt': 'fido-u2f',
    }))

    rp.register(
        b64encode(client_data_json),
        attestation_object,
        email,
        validate_cert_attributes=False,
    )
