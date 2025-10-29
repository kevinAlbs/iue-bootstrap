"""
Test accessKeyId form of KMS credentials.

Testing pymongo 4.15.3 and pymongocrypt 1.16.0 results in error:
> ValueError: kms_providers['azure'] must contain 'clientId' and 'clientSecret'

"""

import os
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption


def main():
    if ("AZURE_ACCESS_TOKEN" not in os.environ):
        raise Exception("AZURE_ACCESS_TOKEN environment variable must be set")
    
    kms_providers = {"azure": {"accessToken": os.environ["AZURE_ACCESS_TOKEN"]}}
    key_vault_namespace = "keyvault.datakeys"
    key_vault_db_name, key_vault_coll_name = key_vault_namespace.split(".", 1)

    client = MongoClient("mongodb://localhost:27777")
    key_vault = client[key_vault_db_name][key_vault_coll_name]
    key_vault.drop()

    client_encryption = ClientEncryption(
        kms_providers,
        key_vault_namespace,
        client,
        client.codec_options,
    )

    key_id = client_encryption.create_data_key("azure")
    print ("Created key: {}".format(key_id))

    client_encryption.close()
    client.close()

if __name__ == "__main__":
    main()
