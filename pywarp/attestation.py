from collections import namedtuple

import cryptography.hazmat.backends
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding

from .cose import COSE
from .fido.metadata import FIDOMetadataClient
from .util import add_pem_header

class AttestationStatement:
    validated_attestation = namedtuple("ValidatedAttestation", "type trust_path credential")

    def __init__(self):
        pass

class TPMAttestationStatement(AttestationStatement):
    def __init__(self):
        raise NotImplementedError()

class FIDOU2FAttestationStatement(AttestationStatement, FIDOMetadataClient):
    def __init__(self, att_stmt):
        self.att_stmt = att_stmt
        assert len(self.att_stmt["x5c"]) == 1
        der_cert = att_stmt["x5c"][0]
        self.att_cert = x509.load_der_x509_certificate(der_cert, cryptography.hazmat.backends.default_backend())
        self.cert_public_key = self.att_cert.public_key()
        self.signature = att_stmt["sig"]

    def validate(self, authenticator_data, rp_id_hash, client_data_hash):
        # See https://www.w3.org/TR/webauthn/#fido-u2f-attestation, "Verification procedure"
        credential = authenticator_data.credential
        public_key_u2f = b'\x04' + credential.public_key.x + credential.public_key.y
        verification_data = b'\x00' + rp_id_hash + client_data_hash + credential.id + public_key_u2f
        assert credential.public_key.ec_id == COSE.ELLIPTIC_CURVES.SECP256R1.value
        assert len(credential.public_key.x) == 32
        assert len(credential.public_key.y) == 32
        self.cert_public_key.verify(self.signature, verification_data, ec.ECDSA(hashes.SHA256()))
        key_id = x509.SubjectKeyIdentifier.from_public_key(self.cert_public_key).digest.hex()
        att_root_cert_chain = self.metadata_for_key_id(key_id)["attestationRootCertificates"]

        # TODO: implement full cert chain validation
        # See https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate.tbs_certificate_bytes
        # See https://github.com/pyca/cryptography/issues/2381
        # See https://github.com/wbond/certvalidator
        assert len(att_root_cert_chain) == 1
        att_root_cert = x509.load_pem_x509_certificate(add_pem_header(att_root_cert_chain[0]).encode(),
                                                       cryptography.hazmat.backends.default_backend())
        att_root_cert.public_key().verify(self.att_cert.signature,
                                          self.att_cert.tbs_certificate_bytes,
                                          padding.PKCS1v15(),
                                          self.att_cert.signature_hash_algorithm)
        return self.validated_attestation(type="Basic", trust_path="x5c", credential=credential)
