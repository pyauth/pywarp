#!/usr/bin/env python

import collections
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pywarp import RelyingPartyManager  # noqa:E402
from pywarp.backends import CredentialStorageBackend  # noqa:E402


class MemoryBackend(CredentialStorageBackend):
    def __init__(self):
        self.users = collections.defaultdict(collections.defaultdict)

    def get_credential_by_email(self, email):
        return self.users[email]["credential"]

    def save_credential_for_user(self, email, credential):
        self.users[email]["credential"] = credential

    def save_challenge_for_user(self, email, challenge, type):
        self.users[email][type + "challenge"] = challenge

    def get_challenge_for_user(self, email, type):
        return self.users[email][type + "challenge"]


class TestPyWARP(unittest.TestCase):
    def test_pywarp(self):
        rp = RelyingPartyManager(__name__, credential_storage_backend=MemoryBackend())
        opts = rp.get_registration_options(email="x")
        self.assertNotEqual(opts, None)


if __name__ == "__main__":
    unittest.main()
