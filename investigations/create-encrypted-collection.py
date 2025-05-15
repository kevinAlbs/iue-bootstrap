# Use `create_encrypted_collection` to create data key, then auto encrypt.
#
# To run:
#   pip install pymongo "pymongo[encryption]"
#   python create_encrypted_collection.py
import os
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption, AutoEncryptionOpts

def with_cec (ce : ClientEncryption, client : MongoClient, kms_providers: dict):
    """
    Create a QE collection with two encrypted fields using create_encrypted_collection.
    """
    ef = {
        "fields": [
            {
                "keyId": None,  # As input, specify `None` (BSON null) to have driver create key.
                "path": "secret",
                "bsonType": "string"
            },
            {
                "keyId": None,  # As input, specify `None` (BSON null) to have driver create key.
                "path": "queryableSecret",
                "bsonType": "string",
                "queries": {"queryType": "equality"},
            }
        ],
    }
    # Get returned encrypted fields with newly created key IDs:
    _, ef = ce.create_encrypted_collection(
        client["db"],
        "coll",
        encrypted_fields=ef,
        kms_provider="local",
    )

    # Create a new client with automatic encryption with the created `encrypted_fields`.
    opts = AutoEncryptionOpts(
        kms_providers,
        "db.keyvault",
        encrypted_fields_map={"db.coll": ef},
    )
    encrypted_client = MongoClient(auto_encryption_opts=opts)
    encrypted_client["db"]["coll"].insert_one({"secret": "foo", "queryableSecret": "bar"})
    encrypted_client.close()

def without_cec (ce : ClientEncryption, client : MongoClient, kms_providers: dict):
    """
    Create a QE collection with two encrypted fields without using create_encrypted_collection.
    """
    keyid1 = ce.create_data_key ("local")
    keyid2 = ce.create_data_key ("local")
    ef = {
        "fields": [
            {
                "keyId": keyid1,
                "path": "secret",
                "bsonType": "string"
            },
            {
                "keyId": keyid2,
                "path": "queryableSecret",
                "bsonType": "string",
                "queries": {"queryType": "equality"},
            }
        ],
    }

    # Create a new client with automatic encryption with the created `encrypted_fields`.
    opts = AutoEncryptionOpts(
        kms_providers,
        "db.keyvault",
        encrypted_fields_map={"db.coll": ef},
    )
    encrypted_client = MongoClient(auto_encryption_opts=opts)
    encrypted_client["db"]["coll"].insert_one({"secret": "foo", "queryableSecret": "bar"})
    encrypted_client.close()

def main():
    local_master_key = os.urandom(96)
    kms_providers = {"local": {"key": local_master_key}}
    key_vault_namespace = "db.keyvault"

    # Create a collection with automatically generated keys:
    client = MongoClient()    
    ce = ClientEncryption(
        kms_providers,
        key_vault_namespace,
        client,
        client.codec_options,
    )

    client.drop_database("db") # Drop to clean from prior test runs.
    with_cec (ce, client, kms_providers)

    client.drop_database("db") # Drop to clean from prior test runs.
    without_cec (ce, client, kms_providers)

    client.close()


if __name__ == "__main__":
    main()
