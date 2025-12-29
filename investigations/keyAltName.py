"""
Show example of encrypting with CSFLE with both UUID and JSON Pointer key references.
To run:

Ensure mongocryptd is on the PATH or is already running.
$ pip install pymongo "pymongo[encryption]"
$ python keyAltName.py
"""

import os
from pymongo import MongoClient
from pymongo.encryption import Algorithm, ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts

def main():
    local_master_key = os.urandom(96)
    kms_providers = {"local": {"key": local_master_key}}

    # The MongoClient used to access the key vault (key_vault_namespace).
    key_vault_client = MongoClient()
    key_vault = key_vault_client["db"]["keyvault"]
    key_vault.drop()

    client_encryption = ClientEncryption(
        kms_providers=kms_providers,
        key_vault_namespace="db.keyvault",
        key_vault_client=key_vault_client,
        codec_options=key_vault_client.codec_options
    )

    test_key_id = client_encryption.create_data_key(
        "local", key_alt_names=["test_key_name"]
    )

    alg = Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic

    schema = {
        "properties": {
            "with_key_id": {
                "encrypt": {
                    "keyId": [test_key_id], # An array of one UUID
                    "bsonType": "string",
                    "algorithm": alg,
                }
            },
            "with_key_alt_name": {
                "encrypt": {
                    "keyId": "/key_name", # JSON Pointer referring to "key_name" field. The "key_name" field value is used to query by keyAltName.
                    "bsonType": "string",
                    "algorithm": alg, # Use Random. Deterministic results in server error: "cannot have a keyId represented by a JSON pointer"
                }
            }
        },
        "bsonType": "object",
    }
    
    schema_map = {"db.coll": schema}

    auto_encryption_opts = AutoEncryptionOpts(
        kms_providers, "db.keyvault", schema_map=schema_map
    )

    client = MongoClient(auto_encryption_opts=auto_encryption_opts)
    coll = client["db"]["coll"]
    coll.drop()

    coll.insert_one({"with_key_id": "foo"})
    coll.insert_one({"with_key_alt_name": "bar", "key_name": "test_key_name"})
    for doc in coll.find():
        print (doc)


if __name__ == "__main__":
    main()
