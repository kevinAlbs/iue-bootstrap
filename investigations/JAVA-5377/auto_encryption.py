# Create a data encryption key, then auto encrypt.
#
# To run:
#   pip install pymongo "pymongo[encryption]"
#   python auto_encryption.py
import os
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption, AutoEncryptionOpts


def main():
    local_master_key = os.urandom(96)
    kms_providers = {"local": {"key": local_master_key}}
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
    key_id = client_encryption.create_data_key("local")
    encrypted_fields = {
        "fields": [
            {
                "keyId": key_id,
                "path": "encryptedIndexed",
                "bsonType": "string",
                "queries": {"queryType": "equality"},
            }
        ],
    }
    client_encryption.close()
    client.close()

    # Create a new client with automatic encryption.
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
