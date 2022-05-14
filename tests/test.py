import unittest

from azure.core.credentials import TokenCredential
from azure.keyvault.keys import KeyClient, KeyOperation
from azure.keyvault.secrets import SecretClient

from noop_credential import NoopCredential
from src.azure_key_repository import AzureKeyRepository
from src.azure_secret_repository import AzureSecretRepository


class TestRepository(unittest.TestCase):

    def test_calling_encrypt_then_decrypt_should_return_original_input_when_called(self):
        # given
        secret_message: str = "a secret message"
        key_name: str = "rsa-key"
        credential: TokenCredential = NoopCredential()
        key_client: KeyClient = KeyClient(vault_url="https://localhost", credential=credential)
        key_client.create_rsa_key(
            name=key_name, size=2048, key_operations=[
                KeyOperation.encrypt, KeyOperation.decrypt, KeyOperation.wrap_key, KeyOperation.unwrap_key])
        under_test: AzureKeyRepository = AzureKeyRepository(
            key_client=key_client, credential=credential, key_name=key_name)

        # when
        encrypted: bytes = under_test.encrypt(clear_text=secret_message)
        decrypted: str = under_test.decrypt(cipher_text=encrypted)

        # then
        key_client.close()
        self.assertEqual(decrypted, secret_message)

    def test_get_database_username_and_password_should_return_original_input_when_called(self):
        # given
        secret_database: str = "database"
        secret_username: str = "username"
        secret_password: str = "password"
        database: str = "db"
        username: str = "admin"
        password: str = "s3cr3t"
        credential: TokenCredential = NoopCredential()
        secret_client: SecretClient = SecretClient(vault_url="https://localhost", credential=credential)
        secret_client.set_secret(name=secret_database, value=database)
        secret_client.set_secret(name=secret_username, value=username)
        secret_client.set_secret(name=secret_password, value=password)
        under_test: AzureSecretRepository = AzureSecretRepository(
            secret_client=secret_client, secret_name_database=secret_database,
            secret_name_username=secret_username, secret_name_password=secret_password)

        # when
        db: str = under_test.get_database()
        usr: str = under_test.get_username()
        pwd: str = under_test.get_password()

        # then
        secret_client.close()
        self.assertEqual(db, database)
        self.assertEqual(usr, username)
        self.assertEqual(pwd, password)


if __name__ == '__main__':
    unittest.main()
