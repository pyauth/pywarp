from email.utils import parseaddr
import json
import re

import cbor2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from .attestation import (FIDOU2FAttestationStatement,
                          PackedAttestationStatement)
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

        self.backend.save_challenge(
            email=email, challenge=challenge, type="registration",
        )
        return options

    def get_authentication_options(self, email):
        credential = self.backend.get_credential(email)
        challenge = token_bytes(32)

        options = {
            "challenge": b64_encode(challenge),
            "timeout": 60 * 1000,
            "allowCredentials": [
                {"type": "public-key", "id": b64_encode(credential.id)}
            ],
        }

        self.backend.save_challenge(
            email=email, challenge=challenge, type="authentication"
        )
        return options

    # https://www.w3.org/TR/webauthn/#registering-a-new-credential
    def register(self, client_data_json, attestation_object, email):
        """Store the credential public key and related metadata on the server
        using the associated storage backend
        """
        attestation = cbor2.loads(attestation_object)

        _, valid_email = parseaddr(email)
        if valid_email and valid_email != email:
            raise Exception("Invalid email address")

        client_data = json.loads(client_data_json)

        assert client_data["type"] == "webauthn.create"

        expect_challenge = self.backend.get_challenge(
            email=email, type="registration"
        )
        assert b64url_decode(client_data["challenge"]) == expect_challenge

        # Verify that the value of C.origin matches the Relying Party's origin.
        if self.rp_id:
            assert "https://" + self.rp_id == client_data["origin"]

        # Verify that the RP ID hash in authData is indeed the SHA-256 hash of
        # the RP ID expected by the RP.
        auth_data = AuthenticatorData(attestation["authData"])
        assert auth_data.user_present

        if attestation["fmt"] == "fido-u2f":
            att_stmt = FIDOU2FAttestationStatement(
                att_stmt=attestation['attStmt']
            )

        elif attestation["fmt"] == "packed":
            att_stmt = PackedAttestationStatement(
                att_stmt=attestation['attStmt']
            )

        else:
            raise Exception("Unknown attestation format " + attestation["fmt"])

        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(client_data_json.encode())
        client_data_hash = hasher.finalize()

        credential = att_stmt.validate(
            auth_data=auth_data, client_data_hash=client_data_hash,
        )

        # TODO: ascertain user identity here
        self.backend.save_credential(email=email, credential=credential)
        return {"registered": True}

    # https://www.w3.org/TR/webauthn/#verifying-assertion
    def verify(self, authenticator_data, client_data_json, signature, user_handle, raw_id, email):
        """Ascertain the validity of credentials supplied by the client user
        agent via navigator.credentials.get()
        """

        _, valid_email = parseaddr(email)
        if valid_email and valid_email != email:
            raise Exception("Invalid email address")

        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(client_data_json)
        client_data_hash = hasher.finalize()
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
