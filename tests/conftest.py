from collections import defaultdict

import pytest
from faker import Faker

from ..pywarp import RelyingPartyManager
from ..pywarp.backends import CredentialStorageBackend


class MemoryBackend(CredentialStorageBackend):
    def __init__(self):
        self.users = defaultdict(defaultdict)

    def get_credential_by_email(self, email):
        return self.users[email]["credential"]

    def save_credential_for_user(self, email, credential):
        self.users[email]["credential"] = credential

    def save_challenge_for_user(self, email, challenge, type):
        self.users[email][type + "challenge"] = challenge

    def get_challenge_for_user(self, email, type):
        return self.users[email][type + "challenge"]


@pytest.fixture
def fake():
    return Faker()


@pytest.fixture
def rp():
    return RelyingPartyManager(
        __name__, credential_storage_backend=MemoryBackend()
    )
