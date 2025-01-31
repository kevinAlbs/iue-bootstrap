"""
Create a QE, CSFLE and unencrypted collection. Dump listCollections results for each.
"""

import os
from pymongo import MongoClient
from pymongo.encryption import (
    Algorithm,
    AutoEncryptionOpts,
    ClientEncryption
)
from bson import json_util


def main():
    local_master_key = os.urandom(96)
    kms_providers = {"local": {"key": local_master_key}}
    key_vault_namespace = "keyvault.datakeys"
    key_vault_db_name, key_vault_coll_name = key_vault_namespace.split(".", 1)

    # Set up the key vault (key_vault_namespace) for this example.
    client = MongoClient()
    key_vault = client[key_vault_db_name][key_vault_coll_name]

    key_vault.drop()

    client_encryption = ClientEncryption(
        kms_providers,
        key_vault_namespace,
        client,
        client.codec_options,
    )

    # Create a new data key for the encryptedField.
    keyid = client_encryption.create_data_key("local")

    encrypted_fields = {
        "fields": [
            {
                "keyId": keyid,
                "path": "encryptedIndexed",
                "bsonType": "string",
                "queries": {"queryType": "equality"},
            }
        ],
    }

    json_schema = {
        "properties": {
            "encryptedField": {
                "encrypt": {
                    "keyId": [keyid],
                    "bsonType": "string",
                    "algorithm": Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic,
                }
            }
        },
        "bsonType": "object",
    }

    opts = AutoEncryptionOpts(
        {"local": {"key": local_master_key}},
        key_vault.full_name,
        key_vault_client=client,
        bypass_auto_encryption=True
    )

    # The MongoClient used to read/write application data.
    encrypted_client = MongoClient(auto_encryption_opts=opts)
    encrypted_client.drop_database("test")
    db = encrypted_client.test

    # Create the collection with encryptedFields.
    db.create_collection("qe", encryptedFields=encrypted_fields)

    # Create the collection with jsonSchema.
    db.create_collection("csfle", validator={"$jsonSchema": json_schema})

    # Create a collection with no schema.
    db.create_collection("unencrypted")

    # Print listCollections results for each:
    for doc in db.list_collections():
        print(json_util.dumps(doc))


    # Cleanup resources.
    client_encryption.close()
    encrypted_client.close()
    client.close()


if __name__ == "__main__":
    main()
