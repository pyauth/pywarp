import hashlib
import json
import re

import cbor2

from .attestation import FIDOU2FAttestationStatement
from .authenticators import AuthenticatorData
from .cose import Algorithms
from .util import b64_encode, b64url_decode
from .util.compat import token_bytes


class RelyingPartyManager:
    def __init__(self, rp_name, rp_id=None, backend=None):
        self.backend = backend
        self.rp_name = rp_name
        self.rp_id = rp_id

    def get_registration_options(self, email, display_name=None, icon=None):
        """Get challenge parameters that will be passed to the user agent's
        navigator.credentials.get() method
        """
        challenge = token_bytes(32)

        options = {
            "challenge": b64_encode(challenge),
            "rp": {
                "name": self.rp_name,
                "id": self.rp_id,
            },
            "user": {
                "id": b64_encode(email.encode()),
                "name": email,
                "displayName": display_name if display_name else email,
                "icon": icon,
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": Algorithms.ES256},
                {"type": "public-key", "alg": Algorithms.ES384},
                {"type": "public-key", "alg": Algorithms.ES512},
            ],
            "timeout": 60 * 1000,
            "excludeCredentials": [],
            "attestation": "direct",
            "extensions": {"loc": True}
        }

        self.backend.save_challenge_for_user(email=email, challenge=challenge, type="registration")
        return options

    def get_authentication_options(self, email):
        credential = self.storage_backend.get_credential(email)
        challenge = token_bytes(32)

        options = {
            "challenge": challenge,
            "timeout": 60 * 1000,
            "allowCredentials": [
                {"type": "public-key", "id": b64_encode(credential.id)}
            ],
        }

        self.backend.save_challenge(email=email, challenge=challenge, type="authentication")
        return options

    # https://www.w3.org/TR/webauthn/#registering-a-new-credential
    def register(self, client_data_json, attestation_object, email):
        "Store the credential public key and related metadata on the server using the associated storage backend"
        authenticator_attestation_response = cbor2.loads(attestation_object)
        email = email.decode()
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise Exception("Invalid email address")
        client_data_hash = hashlib.sha256(client_data_json).digest()
        client_data = json.loads(client_data_json)
        assert client_data["type"] == "webauthn.create"
        print("client data", client_data)
        expect_challenge = self.backend.get_challenge(email=email, type="registration")
        assert b64url_decode(client_data["challenge"]) == expect_challenge
        print("expect RP ID:", self.rp_id)
        if self.rp_id:
            assert "https://" + self.rp_id == client_data["origin"]
        # Verify that the value of C.origin matches the Relying Party's origin.
        # Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP.
        authenticator_data = AuthenticatorData(authenticator_attestation_response["authData"])
        assert authenticator_data.user_present
        # If user verification is required for this registration,
        # verify that the User Verified bit of the flags in authData is set.
        assert authenticator_attestation_response["fmt"] == "fido-u2f"
        att_stmt = FIDOU2FAttestationStatement(authenticator_attestation_response['attStmt'])
        attestation = att_stmt.validate(authenticator_data,
                                        rp_id_hash=authenticator_data.rp_id_hash,
                                        client_data_hash=client_data_hash)
        credential = attestation.credential
        # TODO: ascertain user identity here
        self.backend.save_credential(email=email, credential=credential)
        return {"registered": True}

    # https://www.w3.org/TR/webauthn/#verifying-assertion
    def verify(self, authenticator_data, client_data_json, signature, user_handle, raw_id, email):
        "Ascertain the validity of credentials supplied by the client user agent via navigator.credentials.get()"
        email = email.decode()
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise Exception("Invalid email address")
        client_data_hash = hashlib.sha256(client_data_json).digest()
        client_data = json.loads(client_data_json)
        assert client_data["type"] == "webauthn.get"
        expect_challenge = self.backend.get_challenge(email=email, type="authentication")
        assert b64url_decode(client_data["challenge"]) == expect_challenge
        print("expect RP ID:", self.rp_id)
        if self.rp_id:
            assert "https://" + self.rp_id == client_data["origin"]
        # Verify that the value of C.origin matches the Relying Party's origin.
        # Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP.
        authenticator_data = AuthenticatorData(authenticator_data)
        assert authenticator_data.user_present
        credential = self.backend.get_credential(email)
        credential.verify(signature, authenticator_data.raw_auth_data + client_data_hash)
        # signature counter check
        return {"verified": True}
