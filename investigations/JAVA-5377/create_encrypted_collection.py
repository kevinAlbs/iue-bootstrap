import os
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption, AutoEncryptionOpts


def main():
    local_master_key = os.urandom(96)
    kms_providers = {"local": {"key": local_master_key}}
    key_vault_namespace = "keyvault.datakeys"

    # Create a collection with automatically generated keys:
    client = MongoClient()
    client_encryption = ClientEncryption(
        kms_providers,
        key_vault_namespace,
        client,
        client.codec_options,
    )
    encrypted_fields = {
        "fields": [
            {
                "keyId": None,  # Specify `None` (BSON null) to have driver create key.
                "path": "encryptedIndexed",
                "bsonType": "string",
                "queries": {"queryType": "equality"},
            }
        ],
    }
    client["db"].drop_collection("coll")  # Drop to clean from prior test runs.
    client_encryption.create_encrypted_collection(
        client["db"], "coll", encrypted_fields=encrypted_fields, kms_provider="local"
    )
    client_encryption.close()
    client.close()

    # Create a new client with automatic encryption. Do not specify `encryptedFieldMap` to fetch `encryptedFields` from the server.
    opts = AutoEncryptionOpts({"local": {"key": local_master_key}}, key_vault_namespace)
    encrypted_client = MongoClient(auto_encryption_opts=opts)
    encrypted_coll = encrypted_client["db"]["coll"]
    # Insert with automatic encryption.
    encrypted_coll.insert_one({"encryptedIndexed": "coll"})
    encrypted_client.close()


if __name__ == "__main__":
    main()
