import os
import unittest

import urllib3
from azure.core.credentials import TokenCredential
from azure.core.pipeline.transport._requests_basic import RequestsTransport
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient, CertificatePolicy
from azure.keyvault.keys import KeyClient, KeyOperation
from azure.keyvault.keys.crypto import CryptographyClient
from azure.keyvault.secrets import SecretClient
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509 import Certificate

from noop_credential import NoopCredential
from src.azure_certificate_repository import AzureCertificateRepository
from src.azure_key_repository import AzureKeyRepository
from src.azure_secret_repository import AzureSecretRepository


lowkey_vault_url: str = os.environ.get("LOWKEY_VAULT_URL")
if not lowkey_vault_url:
    lowkey_vault_url = "https://localhost:8443"

class TestRepository(unittest.TestCase):

    def test_calling_encrypt_then_decrypt_should_return_original_input_when_called(self):
        # given
        secret_message: str = "a secret message"
        key_name: str = "rsa-key"
        # ignore SSL errors because we are using a self-signed certificate
        transport_keys = RequestsTransport(connection_verify=False)
        transport_crypto = RequestsTransport(connection_verify=False)
        credential: TokenCredential = NoopCredential()
        key_client: KeyClient = KeyClient(
            vault_url=lowkey_vault_url,
            credential=credential,
            verify_challenge_resource=False,
            transport=transport_keys,
            api_version="7.6"
        )
        key_client.create_rsa_key(
            name=key_name, size=2048, key_operations=[
                KeyOperation.encrypt, KeyOperation.decrypt, KeyOperation.wrap_key, KeyOperation.unwrap_key])
        under_test: AzureKeyRepository = AzureKeyRepository(
            key_client=key_client, credential=credential, key_name=key_name)
        crypto_client: CryptographyClient = CryptographyClient(
            key=under_test.get_key_id(),
            credential=credential,
            verify_challenge_resource=False,
            api_version="7.6",
            transport=transport_crypto)

        # when
        encrypted: bytes = under_test.encrypt(clear_text=secret_message, client=crypto_client)
        decrypted: str = under_test.decrypt(cipher_text=encrypted, client=crypto_client)

        # then
        key_client.close()
        crypto_client.close()
        self.assertEqual(secret_message, decrypted)

    def test_get_database_username_and_password_should_return_original_input_when_called(self):
        # given
        secret_database: str = "database"
        secret_username: str = "username"
        secret_password: str = "password"
        database: str = "db"
        username: str = "admin"
        password: str = "s3cr3t"
        # ignore SSL errors because we are using a self-signed certificate
        transport = RequestsTransport(connection_verify=False)
        credential: TokenCredential = NoopCredential()
        secret_client: SecretClient = SecretClient(
            vault_url=lowkey_vault_url,
            credential=credential,
            verify_challenge_resource=False,
            transport=transport,
            api_version="7.6"
        )
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
        self.assertEqual(database, db)
        self.assertEqual(username, usr)
        self.assertEqual(password, pwd)

    def test_get_certificate_and_get_key_should_return_generated_cert_and_key_when_called(self):
        # given
        certificate_name: str = "certificate"
        # ignore SSL errors because we are using a self-signed certificate
        transport_secrets = RequestsTransport(connection_verify=False)
        transport_certs = RequestsTransport(connection_verify=False)
        credential: TokenCredential = NoopCredential()
        secret_client: SecretClient = SecretClient(
            vault_url=lowkey_vault_url,
            credential=credential,
            verify_challenge_resource=False,
            transport=transport_secrets,
            api_version="7.6"
        )
        certificate_client: CertificateClient = CertificateClient(
            vault_url=lowkey_vault_url,
            credential=credential,
            verify_challenge_resource=False,
            transport=transport_certs,
            api_version="7.6"
        )

        subject_name: str = "CN=example.com"
        policy: CertificatePolicy = CertificatePolicy(
            issuer_name="Self",
            subject=subject_name,
            key_curve_name="P-256",
            key_type="EC",
            validity_in_months=12,
            content_type="application/x-pkcs12"
        )
        certificate_client.begin_create_certificate(certificate_name=certificate_name, policy=policy).wait()
        certificate_client.close()

        under_test: AzureCertificateRepository = AzureCertificateRepository(
            secret_client=secret_client, secret_name_certificate=certificate_name)

        # when
        key: EllipticCurvePrivateKey = under_test.get_key()
        cert: Certificate = under_test.get_certificate()

        # then
        secret_client.close()
        self.assertEqual(subject_name, cert.subject.rdns[0].rfc4514_string())
        self.assertEqual("secp256r1", key.curve.name)


class TestRepositoryWithManagedIdentity(unittest.TestCase):

    def test_calling_encrypt_then_decrypt_should_return_original_input_when_called(self):
        # given
        secret_message: str = "a secret message"
        key_name: str = "rsa-key"
        # ignore SSL errors because we are using a self-signed certificate
        transport_keys = RequestsTransport(connection_verify=False)
        transport_crypto = RequestsTransport(connection_verify=False)
        credential = DefaultAzureCredential()  # Will use Managed Identity via the Assumed Identity container
        key_client: KeyClient = KeyClient(
            vault_url=lowkey_vault_url,
            credential=credential,
            verify_challenge_resource=False,
            transport=transport_keys,
            api_version="7.6"
        )
        key_client.create_rsa_key(
            name=key_name, size=2048, key_operations=[
                KeyOperation.encrypt, KeyOperation.decrypt, KeyOperation.wrap_key, KeyOperation.unwrap_key])
        under_test: AzureKeyRepository = AzureKeyRepository(
            key_client=key_client, credential=credential, key_name=key_name)
        crypto_client: CryptographyClient = CryptographyClient(
            key=under_test.get_key_id(),
            credential=credential,
            verify_challenge_resource=False,
            api_version="7.6",
            transport=transport_crypto)

        # when
        encrypted: bytes = under_test.encrypt(clear_text=secret_message, client=crypto_client)
        decrypted: str = under_test.decrypt(cipher_text=encrypted, client=crypto_client)

        # then
        key_client.close()
        crypto_client.close()
        self.assertEqual(secret_message, decrypted)

    def test_get_database_username_and_password_should_return_original_input_when_called(self):
        # given
        secret_database: str = "database"
        secret_username: str = "username"
        secret_password: str = "password"
        database: str = "db"
        username: str = "admin"
        password: str = "s3cr3t"
        # ignore SSL errors because we are using a self-signed certificate
        transport = RequestsTransport(connection_verify=False)
        credential = DefaultAzureCredential()  # Will use Managed Identity via the Assumed Identity container
        secret_client: SecretClient = SecretClient(
            vault_url=lowkey_vault_url,
            credential=credential,
            verify_challenge_resource=False,
            transport=transport,
            api_version="7.6"
        )
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
        self.assertEqual(database, db)
        self.assertEqual(username, usr)
        self.assertEqual(password, pwd)

    def test_get_certificate_and_get_key_should_return_generated_cert_and_key_when_called(self):
        # given
        certificate_name: str = "certificate"
        # ignore SSL errors because we are using a self-signed certificate
        transport_secrets = RequestsTransport(connection_verify=False)
        transport_certs = RequestsTransport(connection_verify=False)
        credential = DefaultAzureCredential()  # Will use Managed Identity via the Assumed Identity container
        secret_client: SecretClient = SecretClient(
            vault_url=lowkey_vault_url,
            credential=credential,
            verify_challenge_resource=False,
            transport=transport_secrets,
            api_version="7.6"
        )
        certificate_client: CertificateClient = CertificateClient(
            vault_url=lowkey_vault_url,
            credential=credential,
            verify_challenge_resource=False,
            transport=transport_certs,
            api_version="7.6"
        )

        subject_name: str = "CN=example.com"
        policy: CertificatePolicy = CertificatePolicy(
            issuer_name="Self",
            subject=subject_name,
            key_curve_name="P-256",
            key_type="EC",
            validity_in_months=12,
            content_type="application/x-pkcs12"
        )
        certificate_client.begin_create_certificate(certificate_name=certificate_name, policy=policy).wait()
        certificate_client.close()

        under_test: AzureCertificateRepository = AzureCertificateRepository(
            secret_client=secret_client, secret_name_certificate=certificate_name)

        # when
        key: EllipticCurvePrivateKey = under_test.get_key()
        cert: Certificate = under_test.get_certificate()

        # then
        secret_client.close()
        self.assertEqual(subject_name, cert.subject.rdns[0].rfc4514_string())
        self.assertEqual("secp256r1", key.curve.name)


if __name__ == '__main__':
    urllib3.disable_warnings()
    unittest.main()
