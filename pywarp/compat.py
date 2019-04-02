try:
    from secrets import token_bytes
except ImportError:
    from os import urandom as token_bytes
