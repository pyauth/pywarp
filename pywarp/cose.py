from enum import IntEnum

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


class Params(IntEnum):
    """
    See https://www.iana.org/assignments/cose
    """
    KTY = 1
    ALG = 3


class KeyTypes(IntEnum):
    OKP = 1
    EC2 = 2
    RSA = 3


class EC2Params(IntEnum):
    Curve = -1
    X = -2
    Y = -3


class RSAParams(IntEnum):
    N = -1
    E = -2
    D = -3


EllipticCurves = {
    1: ec.SECP256R1,
    2: ec.SECP384R1,
    3: ec.SECP521R1,
}


class Algorithms(IntEnum):
    ES256 = -7
    ES384 = -35
    ES512 = -36


SignatureAlgorithms = {
    -7: hashes.SHA256,
    -35: hashes.SHA384,
    -36: hashes.SHA512,
}
