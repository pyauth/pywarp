import json, base64
from functools import lru_cache

import cryptography.hazmat.backends
from cryptography import x509
import jwt

from ..util import add_pem_header

try:
    from botocore.vendored import requests
except ImportError:
    import requests

class FIDOMetadataClient:
    mds_url = "https://mds.fidoalliance.org/"
    _metadata_toc = None

    @property
    def metadata_toc(self):
        if self._metadata_toc is None:
            res = requests.get(self.mds_url)
            res.raise_for_status()
            jwt_header = jwt.get_unverified_header(res.content)
            assert jwt_header["alg"] == "ES256"
            cert = x509.load_pem_x509_certificate(add_pem_header(jwt_header["x5c"][0]).encode(),
                                                  cryptography.hazmat.backends.default_backend())
            self._metadata_toc = jwt.decode(res.content, key=cert.public_key(), algorithms=["ES256"])
        return self._metadata_toc

    @lru_cache(64)
    def metadata_for_key_id(self, key_id):
        for e in self.metadata_toc["entries"]:
            if key_id in e.get("attestationCertificateKeyIdentifiers", []):
                break
        else:
            raise KeyError("No metadata found for key ID {}".format(key_id))
        res = requests.get(e["url"])
        res.raise_for_status()
        return json.loads(base64.b64decode(res.content).decode())
