import datetime
from collections import defaultdict

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import NameOID
from faker import Faker

from ..pywarp import RelyingPartyManager
from ..pywarp.backends import CredentialStorageBackend


class MemoryBackend(CredentialStorageBackend):
    def __init__(self):
        self.users = defaultdict(defaultdict)

    def get_credential(self, email):
        return self.users[email]["credential"]

    def save_credential(self, email, credential):
        self.users[email]["credential"] = credential

    def save_challenge(self, email, challenge, type):
        self.users[email][type + "challenge"] = challenge

    def get_challenge(self, email, type):
        return self.users[email][type + "challenge"]


@pytest.fixture
def att_cert(private_key, public_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'ACME Corporation'),
        x509.NameAttribute(
            NameOID.ORGANIZATIONAL_UNIT_NAME, 'Authenticator Attestation'
        ),
        x509.NameAttribute(NameOID.COMMON_NAME, 'PyWARP'),
    ])

    now = datetime.datetime.utcnow()

    return x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(public_key) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(now) \
        .not_valid_after(now + datetime.timedelta(days=1)) \
        .sign(private_key, hashes.SHA256(), default_backend())


@pytest.fixture
def attested_data(credential_id, public_numbers):
    aaguid = bytes(x % 8 + 1 for x in range(16))
    x, y = public_numbers.x, public_numbers.y

    return b''.join([
        aaguid,  # aaguid
        len(credential_id).to_bytes(2, 'big'),  # credentialIdLength
        credential_id,  # credentialId
        cbor2.dumps({
            1: 2,  # EC2 key type
            3: -7,  # ES256 signature algorithm
            -1: 1,  # P-256 curve
            -2: x.to_bytes((x.bit_length() + 7) // 8, 'big'),
            -3: y.to_bytes((y.bit_length() + 7) // 8, 'big'),
        }),
    ])


@pytest.fixture
def credential_id():
    return bytes(x % 8 + 1 for x in range(16))


@pytest.fixture
def fake():
    return Faker()


@pytest.fixture
def private_key():
    return ec.generate_private_key(ec.SECP256R1(), default_backend())


@pytest.fixture
def public_key(private_key):
    return private_key.public_key()


@pytest.fixture
def public_numbers(public_key):
    return public_key.public_numbers()


@pytest.fixture
def rp():
    return RelyingPartyManager(__name__, backend=MemoryBackend())
