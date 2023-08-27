![LowkeyVault](https://raw.githubusercontent.com/nagyesta/lowkey-vault/main/.github/assets/LowkeyVault-logo-full.png)

[![GitHub license](https://img.shields.io/github/license/nagyesta/lowkey-vault-example-python?color=informational)](https://raw.githubusercontent.com/nagyesta/lowkey-vault-example-python/main/LICENSE)
[![Python package](https://img.shields.io/github/actions/workflow/status/nagyesta/lowkey-vault-example-python/python.yml?logo=github&branch=main)](https://github.com/nagyesta/lowkey-vault-example-python/actions/workflows/python.yml)
[![Lowkey secure](https://img.shields.io/badge/lowkey-secure-0066CC)](https://github.com/nagyesta/lowkey-vault)

# Lowkey Vault - Example Python

This is an example for [Lowkey Vault](https://github.com/nagyesta/lowkey-vault). It demonstrates a basic scenario where
a key is used for encrypt/decrypt operations and database connection specific credentials as well as getting a PKCS12 
store with a certificate and matching private key inside.

### Points of interest

* [Key "repository"](src/azure_key_repository.py)
* [Secret "repository"](src/azure_secret_repository.py)
* [Certificate "repository"](src/azure_certificate_repository.py)
* [Empty credentials for connecting to Lowkey Vault](tests/noop_credential.py) (not needed if [Assumed Identity](https://github.com/nagyesta/assumed-identity) is used)
* [Tests](tests/test.py)
  * TestRepository is using [NoopCredential](tests/noop_credential.py) for authentication to demonstrate integration with
    * Secrets
    * Keys
    * Certificates
  * TestRepositoryWithManagedIdentity is performing exactly the same but, it is using the DefaultAzureCredential with [Assumed Identity](https://github.com/nagyesta/assumed-identity)

### Usage

1. Start [Lowkey Vault](https://github.com/nagyesta/lowkey-vault) and [Assumed Identity](https://github.com/nagyesta/assumed-identity)
   1. Either by following the steps [here](https://github.com/nagyesta/lowkey-vault#quick-start-guide) and [here](https://github.com/nagyesta/assumed-identity#usage).
   2. Or running ```docker-compose up -d```
2. Set ```REQUESTS_CA_BUNDLE``` environment variable to reference [lowkeyvault.pem](lowkeyvault.pem)
3. If you are not using the default `169.254.169.254:80` address for Assumed Identity (because for example you are running it in the cloud)
   1. Set ```AZURE_POD_IDENTITY_AUTHORITY_HOST``` environment variable to point to the Assumed Identity base URL e.g., http://localhost:8080
   2. Set ```IMDS_ENDPOINT``` environment variable to point to the Assumed Identity base URL e.g., http://localhost:8080
   3. Set ```IDENTITY_ENDPOINT``` environment variable to point to the `/metadata/identity/oauth2/token` path of Assumed Identity e.g., http://localhost:8080/metadata/identity/oauth2/token
4. Run the tests

Note: In order to better understand what is needed in general to make similar examples work, please find a generic overview 
[here](https://github.com/nagyesta/lowkey-vault/wiki/Example:-How-can-you-use-Lowkey-Vault-in-your-tests).

### Note

I am not a professional Python developer. Please do not judge me by the code quality. I am open to any suggestions and
improvements.
