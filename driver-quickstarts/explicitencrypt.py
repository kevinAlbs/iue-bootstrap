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

    client = MongoClient()
    key_vault = client[key_vault_db_name][key_vault_coll_name]
    key_vault.drop()

    client_encryption = ClientEncryption(
        kms_providers,
        key_vault_namespace,
        # The MongoClient to use for reading/writing to the key vault.
        # This can be the same MongoClient used by the main application.
        client,
        # The CodecOptions class used for encrypting and decrypting.
        # This should be the same CodecOptions instance you have configured
        # on MongoClient, Database, or Collection.
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
                "queries": {"queryType": "equality", "contention": 8},
            }
        ],
    }

    opts = AutoEncryptionOpts(
        {"local": {"key": local_master_key}},
        key_vault.full_name,
        bypass_query_analysis=True,
        key_vault_client=client,
    )

    # The MongoClient used to read/write application data.
    encrypted_client = MongoClient(auto_encryption_opts=opts)
    encrypted_client.drop_database("test")
    db = encrypted_client.test

    # Create the collection with encrypted fields.
    coll = db.create_collection("coll", encryptedFields=encrypted_fields)

    # Create encrypted payloads:
    insert_payload = client_encryption.encrypt(123, contention_factor=8, algorithm=Algorithm.INDEXED)

    # Insert the payloads.
    coll.insert_one({"secret": insert_payload})

    # Cleanup resources.
    client_encryption.close()
    encrypted_client.close()
    client.close()


if __name__ == "__main__":
    main()
