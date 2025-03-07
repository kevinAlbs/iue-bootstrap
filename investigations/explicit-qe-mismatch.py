"""
Shows server error on insert of QE payload when CSFLE payload is also present.
QE and CSFLE are incompatible.
"""

import os
from pymongo import MongoClient
from pymongo.encryption import (
    Algorithm,
    AutoEncryptionOpts,
    ClientEncryption,
    RangeOpts
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
                "path": "qe_range",
                "bsonType": "int",
                "queries": {"queryType": "range", "min": 0, "max": 100, "contention": 0},
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
    qe_range_payload = client_encryption.encrypt(
        12, Algorithm.RANGE, key_id, contention_factor=0, range_opts=RangeOpts(min=0, max=100)
    )

    csfle_deterministic = client_encryption.encrypt(
        12, Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic, key_id
    )

    # Insert the payloads.
    coll.insert_one(
        {
            "qe_range": qe_range_payload, # Encrypted with "Range" (QE)
            "csfle_deterministic": csfle_deterministic # Encrypted with "Deterministic" (CSFLE)
        }
    )
    # Gets server error: "Unexpected encrypted payload type: 1"

    # Cleanup resources.
    client_encryption.close()
    encrypted_client.close()
    client.close()


if __name__ == "__main__":
    main()
