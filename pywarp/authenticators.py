import struct

from .credentials import Credential


class AuthenticatorData:
    def __init__(self, auth_data):
        self.raw_auth_data = auth_data
        self.rp_id_hash, flags, self.signature_counter = struct.unpack(">32s1sI", auth_data[:37])
        flags = [bool(int(i)) for i in format(ord(flags), "08b")]
        (self.extension_data_included,
         self.attested_credential_data_included, _, _, _,
         self.user_verified, _,
         self.user_present) = flags
        self.credential = None
        if self.attested_credential_data_included:
            aaguid, credential_id_length = struct.unpack(">16sH", auth_data[37:55])
            credential_id = auth_data[55:55 + credential_id_length]
            cose_credential_public_key = auth_data[55 + credential_id_length:]
            self.credential = Credential(credential_id=credential_id, credential_public_key=cose_credential_public_key)
