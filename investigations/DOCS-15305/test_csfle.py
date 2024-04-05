# Test the behavior described in DOCS-15305
# > For FLE 1, any validator provided that includes $jsonSchema must match the schema in the schema map exactly.
# This statement is incorrect. It is possible to modify the $jsonSchema with `collMod`. This is due to changes in MONGOCRYPT-463. libmongocrypt prefers the schema from the `collMod` command.
#
# To run:
#   pip install pymongo "pymongo[encryption]"
#   export PATH="${PATH}:/path/to/directory/containing/mongocryptd"
#   python auto_encryption.py
import os
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption, AutoEncryptionOpts, Algorithm
import bson


def main():
    local_master_key = os.urandom(96)
    kms_providers = {"local": {"key": local_master_key}}
    key_vault_namespace = "keyvault.datakeys"

    client = MongoClient()
    client.drop_database("db")  # Clear data.

    # Create a data key
    client_encryption = ClientEncryption(
        kms_providers,
        key_vault_namespace,
        client,
        client.codec_options,
    )
    key_id = client_encryption.create_data_key("local")
    client_encryption.close()

    json_schema = {
        "properties": {
            "secret": {
                "encrypt": {
                    "keyId": [key_id],
                    "bsonType": "string",
                    "algorithm": Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic,
                }
            }
        },
        "bsonType": "object",
    }
    # Create a new client with automatic encryption.
    opts = AutoEncryptionOpts(
        kms_providers,
        key_vault_namespace,
        schema_map={"db.coll": json_schema},
    )
    encrypted_client = MongoClient(auto_encryption_opts=opts)
    # Create collection.
    encrypted_client["db"].create_collection("coll")
    # Try to do a collMod with a modified JSON Schema.
    json_schema_2 = {
        "properties": {
            "secret2": {
                "encrypt": {
                    "keyId": [key_id],
                    "bsonType": "string",
                    "algorithm": Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic,
                }
            }
        },
        "bsonType": "object",
    }
    encrypted_client["db"].command(
        {
            "collMod": "coll",
            "validator": {"$jsonSchema": json_schema_2},
        }
    )  # Does not error.

    # Verify auto encryption works. The local schema is preferred.
    encrypted_client["db"]["coll"].insert_one({"secret": "foo"})
    got = client["db"]["coll"].find_one()  # Use unencrypted client to get ciphertext.
    assert isinstance(got["secret"], bson.Binary)
    encrypted_client.close()
    client.close()


if __name__ == "__main__":
    main()
    print("Example finished")
