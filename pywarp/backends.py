from .credentials import Credential

class CredentialStorageBackend:
    def __init__(self):
        raise NotImplementedError("Implementers should subclass CredentialStorageBackend and pass the subclass instance"
                                  " when instantiating RelyingPartyManager.")

    def get_credential_by_email(self, email):
        raise NotImplementedError()

    def save_credential_for_user(self, email, credential):
        raise NotImplementedError()

    def save_challenge_for_user(self, email, challenge, type):
        raise NotImplementedError()

    def get_challenge_for_user(self, email, type):
        raise NotImplementedError()

class DynamoBackend(CredentialStorageBackend):
    def __init__(self):
        import pynamodb.models, pynamodb.attributes

        class UserModel(pynamodb.models.Model):
            class Meta:
                table_name = "pywarp-users"
            email = pynamodb.attributes.UnicodeAttribute(hash_key=True)
            registration_challenge = pynamodb.attributes.BinaryAttribute(null=True)
            authentication_challenge = pynamodb.attributes.BinaryAttribute(null=True)
            credential_id = pynamodb.attributes.BinaryAttribute(null=True)
            credential_public_key = pynamodb.attributes.BinaryAttribute(null=True)
        self.UserModel = UserModel
        self.UserModel.create_table(read_capacity_units=1, write_capacity_units=1, wait=True)

    def upsert(self, email, **values):
        try:
            user = self.UserModel.get(email)
            user.update(actions=[getattr(self.UserModel, k).set(v) for k, v in values.items()])
        except self.UserModel.DoesNotExist:
            user = self.UserModel(email)
            for k, v in values.items():
                setattr(user, k, v)
            user.save()

    def get_credential_by_email(self, email):
        user = self.UserModel.get(email)
        return Credential(credential_id=user.credential_id, credential_public_key=user.credential_public_key)

    def save_credential_for_user(self, email, credential):
        self.upsert(email, credential_id=credential.id, credential_public_key=bytes(credential.public_key))

    def save_challenge_for_user(self, email, challenge, type):
        assert type in {"registration", "authentication"}
        self.upsert(email, **{type + "_challenge": challenge})

    def get_challenge_for_user(self, email, type):
        assert type in {"registration", "authentication"}
        user = self.UserModel.get(email)
        return getattr(user, type + "_challenge")
