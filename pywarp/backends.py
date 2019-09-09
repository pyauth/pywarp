class CredentialStorageBackend:
    def __init__(self):
        raise NotImplementedError(
            "Implementers should subclass CredentialStorageBackend and pass "
            "the subclass instance when instantiating RelyingPartyManager."
        )

    def get_credential(self, email):
        raise NotImplementedError()

    def save_credential(self, email, credential):
        raise NotImplementedError()

    def save_challenge(self, email, challenge, type):
        raise NotImplementedError()

    def get_challenge(self, email, type):
        raise NotImplementedError()
