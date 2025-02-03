"""
Test error conditions for DRIVERS-2309.
"""

import os
from pymongo import MongoClient
from pymongo.encryption import (
    Algorithm,
    AutoEncryptionOpts,
    ClientEncryption
)


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
                "path": "qeEncrypted",
                "bsonType": "string"
            }
        ],
    }

    json_schema = {
        "properties": {
            "csfleEncrypted": {
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
        key_vault_client=client
    )

    # The MongoClient used to read/write application data.
    encrypted_client = MongoClient(auto_encryption_opts=opts)
    encrypted_client.drop_database("test")
    db = encrypted_client.test

    # Does not error!?
    db.create_collection("qe", validator={"qeEncrypted": "foo"}, encryptedFields=encrypted_fields)

    # Errors?!
    try:
        db.create_collection("csfle", validator={"$jsonSchema": json_schema, "unrelated": "foo"})
    except Exception as exp:
        print ("Failed to create collection 'csfle': {}".format(str(exp)))

    # Can't actually use `qe`: "schema requires encryption, but collection JSON schema validator has siblings"
    # db.qe.find_one({})
    # # Print listCollections results for each:
    # for doc in db.list_collections():
    #     print(json_util.dumps(doc, indent=4))


    # Cleanup resources.
    client_encryption.close()
    encrypted_client.close()
    client.close()


if __name__ == "__main__":
    main()
