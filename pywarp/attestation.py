from collections import namedtuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.x509.oid import NameOID

from .fido.metadata import FIDOMetadataClient

ValidatedAttestation = namedtuple(
    'ValidatedAttestation', 'credential trust_path type'
)


def byte_length(n):
    return (n.bit_length() + 7) // 8


class AttestationStatement:
    def __init__(self, att_stmt):
        self.att_stmt = att_stmt

        cert, *_ = att_stmt["x5c"]

        self.att_cert = x509.load_der_x509_certificate(
            cert, default_backend()
        )
        self.public_key = self.att_cert.public_key()
        self.signature = att_stmt["sig"]

    def validate(self, *args, **kwargs):
        raise NotImplementedError()


class PackedAttestationStatement(AttestationStatement):
    def validate(self, auth_data, client_data_hash, validate_cert_attributes):
        # https://www.w3.org/TR/webauthn/#packed-attestation
        verification = auth_data.raw_auth_data + client_data_hash
        key = self.att_cert.public_key()
        key.verify(self.signature, verification, ec.ECDSA(hashes.SHA256()))

        # https://www.w3.org/TR/webauthn/#packed-attestation-cert-requirements
        version = self.att_cert.version
        assert version == x509.Version.v3

        attestation_type = 'basic'
        if validate_cert_attributes:
            subj = self.att_cert.subject

            c, *_ = subj.get_attributes_for_oid(NameOID.COUNTRY_NAME)
            assert len(c.value) == 2

            o, *_ = subj.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            assert o.value

            ou, *_ = subj.get_attributes_for_oid(
                NameOID.ORGANIZATIONAL_UNIT_NAME
            )
            assert ou.value == "Authenticator Attestation"

            cn, *_ = subj.get_attributes_for_oid(NameOID.COMMON_NAME)
            assert cn.value

        return ValidatedAttestation(
            auth_data.credential, 'x5c', attestation_type,
        )


class TPMAttestationStatement(AttestationStatement):
    def __init__(self):
        raise NotImplementedError()


class FIDOU2FAttestationStatement(AttestationStatement, FIDOMetadataClient):
    def validate(self, auth_data, client_data_hash, validate_cert_attributes):
        # See https://www.w3.org/TR/webauthn/#fido-u2f-attestation,
        # "Verification procedure"
        credential = auth_data.credential

        public_numbers = credential.public_numbers
        assert byte_length(public_numbers.x) == 32
        assert byte_length(public_numbers.y) == 32

        public_key_u2f = b''.join([
            b'\x04',
            public_numbers.x.to_bytes(32, 'big'),
            public_numbers.y.to_bytes(32, 'big'),
        ])

        verification = b''.join([
            b'\x00',
            auth_data.rp_id_hash,
            client_data_hash,
            credential.id,
            public_key_u2f,
        ])

        key = self.att_cert.public_key()
        key.verify(self.signature, verification, ec.ECDSA(hashes.SHA256()))

        attestation_type = 'basic'
        if validate_cert_attributes:
            key_id = x509.SubjectKeyIdentifier.from_public_key(self.public_key)
            metadata = self.metadata_for_key_id(key_id.digest.hex())
            att_root_cert_chain = metadata["attestationRootCertificates"]

            # TODO: implement full cert chain validation
            # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate.tbs_certificate_bytes
            # https://github.com/pyca/cryptography/issues/2381
            # https://github.com/wbond/certvalidator
            assert len(att_root_cert_chain) == 1
            att_root_cert = x509.load_der_x509_certificate(
                att_root_cert_chain[0].encode(), backend=default_backend()
            )
            att_root_cert.public_key().verify(
                self.att_cert.signature,
                self.att_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                self.att_cert.signature_hash_algorithm
            )

        return ValidatedAttestation(credential, 'x5c', attestation_type)
