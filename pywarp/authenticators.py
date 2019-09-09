from enum import IntEnum

import cbor2

from .credentials import Credential


class Flags(IntEnum):
    UP = 1 << 0
    UV = 1 << 2
    AT = 1 << 6
    ED = 1 << 7


class AuthenticatorData:
    def __init__(self, data):
        self.raw_auth_data = data

        self.rp_id_hash = data[:32]
        self.flags = data[32]
        self.sign_count = data[33:37]

        if self.attested_credential_data_included:
            # aaguid = UUID(bytes=data[37:53])
            cred_id_length = int.from_bytes(data[53:55], 'big')
            cred_id = data[55:55 + cred_id_length]
            public_key = cbor2.loads(data[55 + cred_id_length:])

            self.credential = Credential(id=cred_id, public_key=public_key)
        else:
            self.credential = None

    @property
    def user_present(self):
        return bool(Flags.UP & self.flags)

    @property
    def user_verified(self):
        return bool(Flags.UV & self.flags)

    @property
    def attested_credential_data_included(self):
        return bool(Flags.AT & self.flags)
