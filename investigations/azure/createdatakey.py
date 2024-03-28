# Create a data encryption key with Azure with a custom 'identityPlatformEndpoint'
#
# To run:
#   pip install pymongo "pymongo[encryption]"
#   python createdatakey.py
import os
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption


def main():
    kms_providers = {
        "azure": {
            "tenantId": os.environ["TEST_AZURE_TENANTID"],
            "clientId": os.environ["TEST_AZURE_CLIENTID"],
            "clientSecret": os.environ["TEST_AZURE_CLIENTSECRET"],
            "identityPlatformEndpoint": "127.0.0.1:12345",  # Use IP literal (not "localhost") to avoid libmongocrypt error: `expected dot separator in host`
        }
    }
    key_vault_namespace = "keyvault.datakeys"

    client = MongoClient()
    client["db"].drop_collection("coll")  # Drop to clean from prior test runs.
    client_encryption = ClientEncryption(
        kms_providers,
        key_vault_namespace,
        client,
        client.codec_options,
    )
    # Create a data key.
    key_id = client_encryption.create_data_key(
        "azure",
        master_key={
            "keyVaultEndpoint": os.environ["TEST_AZURE_KEYVAULTENDPOINT"],
            "keyName": os.environ["TEST_AZURE_KEYNAME"],
        },
    )
    print("Created key with ID: {}".format(key_id))


if __name__ == "__main__":
    main()
