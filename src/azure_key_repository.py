from azure.core.credentials import TokenCredential
from azure.core.pipeline.transport._requests_basic import RequestsTransport
from azure.keyvault.keys import KeyClient, KeyVaultKey
from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm, EncryptResult, DecryptResult


class AzureKeyRepository(object):
    def __init__(self, key_client: KeyClient, credential: TokenCredential, key_name: str):
        self.credential = credential
        self.key_client = key_client
        self.key_name = key_name

    def encrypt(self, clear_text: str, client: CryptographyClient):
        text_as_bytes: bytes = bytes(clear_text.encode("utf-8"))
        encrypted: EncryptResult = client.encrypt(algorithm=EncryptionAlgorithm.rsa_oaep_256, plaintext=text_as_bytes)
        return encrypted.ciphertext

    def decrypt(self, cipher_text: bytes, client: CryptographyClient):
        decrypted: DecryptResult = client.decrypt(algorithm=EncryptionAlgorithm.rsa_oaep_256, ciphertext=cipher_text)
        plaintext_bytes: bytes = decrypted.plaintext
        return plaintext_bytes.decode("utf-8")

    def get_key_id(self):
        return self.key_client.get_key(name=self.key_name).id

