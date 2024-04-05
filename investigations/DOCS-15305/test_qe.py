# Test the behavior described in DOCS-15305
#
# To run:
#   pip install pymongo "pymongo[encryption]"
#   export PATH="${PATH}:/path/to/directory/containing/mongocryptd"
#   python auto_encryption.py
import os
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption, AutoEncryptionOpts, Algorithm


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

    """
    From DOCS-15305:
    > For FLE 2, a $jsonSchema that references an encrypted field will always result in a query analysis error because $jsonSchema is not supported in query analysis
    """
    encrypted_fields = {
        "fields": [
            {
                "keyId": key_id,
                "path": "qe_secret",
                "bsonType": "string",
                "queries": {"queryType": "equality"},
            }
        ],
    }
    # Create a new client with automatic encryption.
    opts = AutoEncryptionOpts(
        kms_providers,
        key_vault_namespace,
        encrypted_fields_map={"db.coll": encrypted_fields},
    )
    encrypted_client = MongoClient(auto_encryption_opts=opts)
    # Create collection with $jsonSchema that references an encrypted field.
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
    got_error = ""
    try:
        encrypted_client["db"].create_collection(
            "coll", validator={"$jsonSchema": json_schema}
        )
    except Exception as e:
        got_error = str(e)
    assert "Encryption-related validator keywords are not allowed" in got_error
    encrypted_client.close()

    client.close()


if __name__ == "__main__":
    main()
    print("Example finished")
