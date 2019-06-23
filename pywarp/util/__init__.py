import textwrap, base64

def b64_encode(b):
    return base64.b64encode(b).decode()

def b64_decode(s):
    return base64.b64decode(s)

def b64url_encode(b):
    return base64.urlsafe_b64encode(b).decode()

def b64url_decode(s):
    return base64.urlsafe_b64decode(b64_restore_padding(s))

def b64_restore_padding(unpadded_b64_string):
    return unpadded_b64_string + '=' * (-len(unpadded_b64_string) % 4)

class Placeholder:
    """
    Used to indicate a value that must be replaced with response-specific data before being sent over the wire.
    """
