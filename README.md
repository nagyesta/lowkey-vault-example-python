![LowkeyVault](https://raw.githubusercontent.com/nagyesta/lowkey-vault/main/.github/assets/LowkeyVault-logo-full.png)

[![GitHub license](https://img.shields.io/github/license/nagyesta/lowkey-vault-example-python?color=informational)](https://raw.githubusercontent.com/nagyesta/lowkey-vault-example-python/main/LICENSE)
[![Python package](https://img.shields.io/github/workflow/status/nagyesta/lowkey-vault-example-python/Python%20package?logo=github)](https://github.com/nagyesta/lowkey-vault-example-python/actions/workflows/python.yml)
[![Lowkey secure](https://img.shields.io/badge/lowkey-secure-0066CC)](https://github.com/nagyesta/lowkey-vault)

# Lowkey Vault - Example Python

This is an example for [Lowkey Vault](https://github.com/nagyesta/lowkey-vault). It demonstrates a basic scenario where
a key is used for encrypt/decrypt operations and database connection specific credentials.

### Points of interest

* [Key "repository"](src/azure_key_repository.py)
* [Secret "repository"](src/azure_secret_repository.py)
* [Empty credentials for connecting to Lowkey Vault](tests/noop_credential.py)
* [Tests](tests/test.py)

### Usage

1. Start Lowkey Vault 
   1. Either by following the steps [here](https://github.com/nagyesta/lowkey-vault#quick-start-guide).
      1. Make sure to use port ```443``` until [this issue](https://github.com/Azure/azure-sdk-for-python/issues/24446) in the Python client is solved.
   2. Or running ```docker-compose up -d```
2. Set ```REQUESTS_CA_BUNDLE``` environment variable to reference [lowkeyvault.pem](lowkeyvault.pem)
3. Run the tests

Note: In order to better understand what is needed in general to make similar examples work, please find a generic overview 
[here](https://github.com/nagyesta/lowkey-vault/wiki/Example:-How-can-you-use-Lowkey-Vault-in-your-tests).

### Note

This is my very first Python project after using it for 2-3 hours, please have mercy when
commenting on code quality!