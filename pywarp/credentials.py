<<<<<<< HEAD
import cbor2
import cryptography.hazmat.backends
from cryptography.hazmat.primitives.asymmetric import ec

from .cose import (EC2Params, EllipticCurves, KeyTypes, Params, RSAParams,
                   SignatureAlgorithms)

=======
from collections import namedtuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
>>>>>>> Cleanup COSE utilities, refactor credentials

from .cose import (EC2Params, EllipticCurves, KeyTypes, Params, RSAParams,
                   SignatureAlgorithms)

# class CredentialPublicKey:
#     def __init__(self, cbor_cose_key):
#         self.cbor_cose_key = cbor_cose_key
#         COSE_key = cbor2.loads(cbor_cose_key)
#         self.key_type = COSE_key[COSE.KTY]
#         self.algorithm = COSE_key[COSE.ALG]
#         if self.key_type == COSE.KEY_TYPES.EC2:
#             self.ec_id = COSE_key[COSE.KEY_TYPE_PARAMS.EC2.EC_ID]
#             self.x = COSE_key[COSE.KEY_TYPE_PARAMS.EC2.X]
#             self.y = COSE_key[COSE.KEY_TYPE_PARAMS.EC2.Y]
#         elif self.key_type == COSE.KEY_TYPES.RSA:
#             self.n = COSE_key[COSE.KEY_TYPE_PARAMS.RSA.N]
#             self.e = COSE_key[COSE.KEY_TYPE_PARAMS.RSA.E]

#     def __bytes__(self):
#         return self.cbor_cose_key
CredentialPublicKey = namedtuple('CredentialPublicKey', 'id public_key')


class Credential:
    def __init__(self, id, public_key):
        self.id = id

        self.key_type = public_key[Params.KTY]
        self.algorithm = public_key[Params.ALG]

        if self.key_type == KeyTypes.EC2:
            curve = EllipticCurves[public_key[EC2Params.Curve]]
            x, y = public_key[EC2Params.X], public_key[EC2Params.Y]

            if isinstance(x, bytes):
                x = int.from_bytes(x, 'big')

            if isinstance(y, bytes):
                y = int.from_bytes(y, 'big')

            self.public_numbers = ec.EllipticCurvePublicNumbers(
                curve=curve(), x=x, y=y
            )

        elif self.key_type == KeyTypes.RSA:
            n, e = public_key[RSAParams.N], public_key[RSAParams.E]

            if isinstance(n, bytes):
                n = int.from_bytes(x, 'big')

            if isinstance(e, bytes):
                e = int.from_bytes(e, 'big')

            self.public_numbers = rsa.RSAPublicNumbers(n=n, e=e)

        self.public_key = CredentialPublicKey(
            id=id, public_key=self.public_numbers.public_key(default_backend())
        )

    def verify(self, signature, data):
        sig_alg = SignatureAlgorithms[self.algorithm]
        self.public_key.verify(signature, data, ec.ECDSA(sig_alg()))
