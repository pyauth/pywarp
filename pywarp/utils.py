import base64


def b64encode(b):
    """
    >>> b64encode(b"pleasure.")
    'cGxlYXN1cmUu'
    >>> b64encode(b"leasure.")
    'bGVhc3VyZS4='
    >>> b64encode(b"easure.")
    'ZWFzdXJlLg=='
    """
    return base64.b64encode(b).decode()


def b64decode(s):
    """
    >>> b64decode(b"cGxlYXN1cmUu")
    b'pleasure.'
    >>> b64decode(b"bGVhc3VyZS4=")
    b'leasure.'
    >>> b64decode(b"ZWFzdXJlLg==")
    b'easure.'
    """
    return base64.b64decode(s)


def b64_restore_padding(string):
    """
    >>> b64_restore_padding("TQ")
    'TQ=='
    >>> b64_restore_padding("TWE")
    'TWE='
    >>> b64_restore_padding("TWFu")
    'TWFu'
    """
    return string + '=' * (-len(string) % 4)
