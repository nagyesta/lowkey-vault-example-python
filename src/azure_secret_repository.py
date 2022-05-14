from azure.keyvault.secrets import SecretClient


class AzureSecretRepository(object):
    def __init__(self, secret_client: SecretClient,
                 secret_name_database: str, secret_name_username: str, secret_name_password: str):
        self.secret_client = secret_client
        self.secret_name_database = secret_name_database
        self.secret_name_username = secret_name_username
        self.secret_name_password = secret_name_password

    secret_name_database: str
    secret_name_username: str
    secret_name_password: str
    secret_client: SecretClient

    def get_database(self):
        return self.secret_client.get_secret(name=self.secret_name_database).value

    def get_username(self):
        return self.secret_client.get_secret(name=self.secret_name_username).value

    def get_password(self):
        return self.secret_client.get_secret(name=self.secret_name_password).value

