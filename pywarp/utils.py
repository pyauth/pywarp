import base64

_urlsafe_translate = bytes.maketrans(b'-_', b'+/')


def _restore_padding(b):
    """
    >>> _restore_padding(b"TQ")
    b'TQ=='
    >>> _restore_padding(b"TWE")
    b'TWE='
    >>> _restore_padding(b"TWFu")
    b'TWFu'
    """
    return b.translate(_urlsafe_translate) + b'=' * (-len(b) % 4)


def b64encode(b):
    """
    >>> b64encode("pleasure.")
    'cGxlYXN1cmUu'
    >>> b64encode("leasure.")
    'bGVhc3VyZS4='
    >>> b64encode("easure.")
    'ZWFzdXJlLg=='
    """
    if isinstance(b, str):
        b = b.encode()
    return base64.b64encode(b).decode()


def b64decode(b):
    """
    >>> b64decode("cGxlYXN1cmUu")
    b'pleasure.'
    >>> b64decode("bGVhc3VyZS4")
    b'leasure.'
    >>> b64decode("ZWFzdXJlLg")
    b'easure.'
    """
    if isinstance(b, str):
        b = b.encode()
    return base64.b64decode(_restore_padding(b))
