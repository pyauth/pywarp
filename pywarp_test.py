#!/usr/bin/env python

import os, sys, unittest, json, collections

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))  # noqa

from pywarp import RelyingPartyManager
from pywarp.backends import CredentialStorageBackend

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

if __name__ == '__main__':
    unittest.main()
