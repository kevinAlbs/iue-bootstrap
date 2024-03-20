# Try (and fail) to auto encrypt with a null `keyId`.
#
# To run:
#   pip install pymongo "pymongo[encryption]"
#   python auto_encryption_requires_keyid.py
import os
from pymongo import MongoClient
from pymongo.encryption import AutoEncryptionOpts
from pymongo.errors import EncryptionError


def main():
    local_master_key = os.urandom(96)
    kms_providers = {"local": {"key": local_master_key}}
    key_vault_namespace = "keyvault.datakeys"

    client = MongoClient()
    client["db"].drop_collection("coll")  # Drop to clean from prior test runs.
    # Expect an error if specifying a NULL `keyId` for automatic encryption:
    threw_exception = False
    encrypted_fields = {
        "fields": [
            {
                "keyId": None,  # Error - keyId is required for automatic encryption!
                "path": "encryptedIndexed",
                "bsonType": "string",
                "queries": {"queryType": "equality"},
            }
        ],
    }
    opts = AutoEncryptionOpts(
        kms_providers,
        key_vault_namespace,
        encrypted_fields_map={"db.coll": encrypted_fields},
    )
    try:
        encrypted_client = MongoClient(auto_encryption_opts=opts)
        encrypted_coll = encrypted_client["db"]["coll"]
        encrypted_coll.insert_one({"encryptedIndexed": "coll"})
        encrypted_client.close()
    except EncryptionError as err:
        threw_exception = True
        assert "expected 'fields.keyId' to be type binary" in str(err)
    assert threw_exception


if __name__ == "__main__":
    main()
