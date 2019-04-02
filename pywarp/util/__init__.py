import textwrap
import base64

PEM_HEADER = "-----BEGIN CERTIFICATE-----"
PEM_FOOTER = "-----END CERTIFICATE-----"


def b64_encode(b):
    """
    >>> b64_encode(b"pleasure.")
    'cGxlYXN1cmUu'
    >>> b64_encode(b"leasure.")
    'bGVhc3VyZS4='
    >>> b64_encode(b"easure.")
    'ZWFzdXJlLg=='
    """
    return base64.b64encode(b).decode()


def b64_decode(s):
    """
    >>> b64_decode(b"cGxlYXN1cmUu")
    b'pleasure.'
    >>> b64_decode(b"bGVhc3VyZS4=")
    b'leasure.'
    >>> b64_decode(b"ZWFzdXJlLg==")
    b'easure.'
    """
    return base64.b64decode(s)


def b64url_encode(b):
    return base64.urlsafe_b64encode(b).decode()


def b64url_decode(s):
    return base64.urlsafe_b64decode(b64_restore_padding(s))


def b64_restore_padding(unpadded_b64_string):
    """
    >>> b64_restore_padding("TQ")
    'TQ=='
    >>> b64_restore_padding("TWE")
    'TWE='
    >>> b64_restore_padding("TWFu")
    'TWFu'
    """
    return unpadded_b64_string + '=' * (-len(unpadded_b64_string) % 4)


def add_pem_header(bare_base64_cert):
    return PEM_HEADER + "\n" + textwrap.fill(bare_base64_cert, 64) + "\n" + PEM_FOOTER
