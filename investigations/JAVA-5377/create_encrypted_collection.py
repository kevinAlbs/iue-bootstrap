# Use `create_encrypted_collection` to create data key, then auto encrypt.
#
# To run:
#   pip install pymongo "pymongo[encryption]"
#   python create_encrypted_collection.py
import os
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption, AutoEncryptionOpts


def main():
    local_master_key = os.urandom(96)
    kms_providers = {"local": {"key": local_master_key}}
    key_vault_namespace = "keyvault.datakeys"

    # Create a collection with automatically generated keys:
    client = MongoClient()
    client["db"].drop_collection("coll")  # Drop to clean from prior test runs.
    client_encryption = ClientEncryption(
        kms_providers,
        key_vault_namespace,
        client,
        client.codec_options,
    )
    _, encrypted_fields = client_encryption.create_encrypted_collection(
        client["db"],
        "coll",
        encrypted_fields={
            "fields": [
                {
                    "keyId": None,  # As input, specify `None` (BSON null) to have driver create key.
                    "path": "encryptedIndexed",
                    "bsonType": "string",
                    "queries": {"queryType": "equality"},
                }
            ],
        },
        kms_provider="local",
    )
    # The returned `encrypted_fields` contains the `keyId` filled in.
    assert encrypted_fields["fields"][0]["keyId"] is not None
    client_encryption.close()
    client.close()

    # Create a new client with automatic encryption with the created `encrypted_fields`.
    opts = AutoEncryptionOpts(
        kms_providers,
        key_vault_namespace,
        encrypted_fields_map={"db.coll": encrypted_fields},
    )
    encrypted_client = MongoClient(auto_encryption_opts=opts)
    encrypted_coll = encrypted_client["db"]["coll"]
    # Insert with automatic encryption.
    encrypted_coll.insert_one({"encryptedIndexed": "coll"})
    encrypted_client.close()


if __name__ == "__main__":
    main()
