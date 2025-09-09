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

    client = MongoClient("mongodb://localhost:27123")
    key_vault = client[key_vault_db_name][key_vault_coll_name]
    key_vault.drop()

    client_encryption = ClientEncryption(
        kms_providers,
        key_vault_namespace,
        client,
        client.codec_options,
    )

    # Create a new data key for the encryptedField.
    key_id = client_encryption.create_data_key("local")

    encrypted_fields = {
        "fields": [
            {
                "keyId": key_id,
                "path": "secret",
                "bsonType": "int",
                # No supported queries.
            }
        ],
    }

    opts = AutoEncryptionOpts(
        {"local": {"key": local_master_key}},
        key_vault.full_name,
        bypass_query_analysis=True, # Bypass query analysis to do explicit encryption.
        key_vault_client=client,
    )

    # Create client with auto encryption:
    encrypted_client = MongoClient("mongodb://localhost:27123", auto_encryption_opts=opts)
    encrypted_client.drop_database("test")
    db = encrypted_client.test

    # Create the collection with encrypted fields:
    coll = db.create_collection("coll", encryptedFields=encrypted_fields)

    # Encrypt payload and insert:
    insert_payload = client_encryption.encrypt(123, algorithm=Algorithm.UNINDEXED, key_id=key_id)
    coll.insert_one({"secret": insert_payload})

    # Cleanup:
    client_encryption.close()
    encrypted_client.close()
    client.close()


if __name__ == "__main__":
    main()
