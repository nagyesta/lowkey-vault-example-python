from azure.core.credentials import TokenCredential
from azure.keyvault.keys import KeyClient, KeyVaultKey
from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm, EncryptResult, DecryptResult


class AzureKeyRepository(object):
    def __init__(self, key_client: KeyClient, credential: TokenCredential, key_name: str):
        self.credential = credential
        self.key_client = key_client
        self.key_name = key_name

    key_name: str
    key_client: KeyClient
    credential: TokenCredential

    def encrypt(self, clear_text: str):
        key: KeyVaultKey = self.key_client.get_key(name=self.key_name)
        text_as_bytes: bytes = bytes(clear_text.encode("utf-8"))
        client: CryptographyClient = CryptographyClient(key=key.id, credential=self.credential, api_version="7.3")
        encrypted: EncryptResult = client.encrypt(algorithm=EncryptionAlgorithm.rsa_oaep_256, plaintext=text_as_bytes)
        client.close()
        return encrypted.ciphertext

    def decrypt(self, cipher_text: bytes):
        key: KeyVaultKey = self.key_client.get_key(name=self.key_name)
        client: CryptographyClient = CryptographyClient(key=key.id, credential=self.credential, api_version="7.3")
        decrypted: DecryptResult = client.decrypt(algorithm=EncryptionAlgorithm.rsa_oaep_256, ciphertext=cipher_text)
        client.close()
        plaintext_bytes: bytes = decrypted.plaintext
        return plaintext_bytes.decode("utf-8")

