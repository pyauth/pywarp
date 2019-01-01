import cbor2
import cryptography.hazmat.backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding

from .cose import COSE

class CredentialPublicKey:
    def __init__(self, cbor_cose_key):
        self.cbor_cose_key = cbor_cose_key
        COSE_key = cbor2.loads(cbor_cose_key)
        print("Init CPK from COSE", COSE_key)
        self.key_type = COSE_key[COSE.KTY]
        self.algorithm = COSE_key[COSE.ALG]
        if self.key_type == COSE.KEY_TYPES.EC2:
            self.ec_id = COSE_key[COSE.KEY_TYPE_PARAMS.EC2.EC_ID]
            self.x = COSE_key[COSE.KEY_TYPE_PARAMS.EC2.X]
            self.y = COSE_key[COSE.KEY_TYPE_PARAMS.EC2.Y]
        elif self.key_type == COSE.KEY_TYPES.RSA:
            self.n = COSE_key[COSE.KEY_TYPE_PARAMS.RSA.N]
            self.e = COSE_key[COSE.KEY_TYPE_PARAMS.RSA.E]

    def __bytes__(self):
        return self.cbor_cose_key

class Credential:
    def __init__(self, credential_id=None, credential_public_key=None):
        self.id = credential_id
        self.public_key = CredentialPublicKey(credential_public_key)

    def verify(self, signature, signed_data):
        ec_curve = getattr(ec, COSE.ELLIPTIC_CURVES(self.public_key.ec_id).name)()
        ec_pk_numbers = ec.EllipticCurvePublicNumbers(int.from_bytes(self.public_key.x, byteorder="big"),
                                                      int.from_bytes(self.public_key.y, byteorder="big"),
                                                      ec_curve)
        ec_public_key = ec_pk_numbers.public_key(cryptography.hazmat.backends.default_backend())
        ec_public_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
