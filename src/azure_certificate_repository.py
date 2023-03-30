import base64

from azure.keyvault.secrets import SecretClient
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates


class AzureCertificateRepository(object):
    def __init__(self, secret_client: SecretClient, secret_name_certificate: str):
        self.secret_client = secret_client
        self.secret_name_certificate = secret_name_certificate

    secret_name_certificate: str
    secret_client: SecretClient

    def get_certificate(self) -> x509.Certificate:
        return self.fetch_pkcs12()[1]

    def get_key(self) -> EllipticCurvePrivateKey:
        return self.fetch_pkcs12()[0]

    def fetch_pkcs12(self):
        secret = self.secret_client.get_secret(name=self.secret_name_certificate).value
        # decode base64 secret
        decoded = base64.b64decode(secret)
        # open decoded secret as PKCS12 file
        return load_key_and_certificates(decoded, b'')
