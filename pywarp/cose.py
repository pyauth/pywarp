from enum import Enum

class COSE:
    """
    See https://www.iana.org/assignments/cose
    """
    KTY = 1
    ALG = 3

    class KEY_TYPES:
        OKP = 1
        EC2 = 2
        RSA = 3

    class KEY_TYPE_PARAMS:
        class EC2:
            EC_ID = -1
            X = -2
            Y = -3

        class RSA:
            N = -1
            E = -2
            D = -3

    class ELLIPTIC_CURVES(Enum):
        SECP256R1 = 1
        SECP384R1 = 2
        SECP521R1 = 3

    class ALGORITHMS:
        ES512 = -36
        ES384 = -35
        ES256 = -7
