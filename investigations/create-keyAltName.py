# create-keyAltName tries to create a QE collection using "keyAltName" in "encryptedFields"
import os
from pymongo import MongoClient
from pymongo.encryption_options import AutoEncryptionOpts

kms_providers = {"local": {"key": os.urandom(96)}}
key_vault_namespace = "keyvault.datakeys"

uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017")

# Drop pre-existing data:
client = MongoClient(uri).db.coll.drop()

encrypted_fields = {
    "fields": [
        {
            "path": "secret",
            "bsonType": "string",
            "keyAltName": "foo",  # TODO: will this work with MONGOCRYPT-432?
        }
    ]
}

# Example 1: encrypted_fields_map is set:
encrypted_client = MongoClient(uri, auto_encryption_opts=AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
    encrypted_fields_map={"db.coll": encrypted_fields},
))
encrypted_client.db.create_collection("coll")


# Example 2: encrypted_fields is only in the 'create' command:
encrypted_client = MongoClient(uri, auto_encryption_opts=AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
    # encrypted_fields_map is not set.
))
encrypted_client.db.create_collection("coll", encrypted_fields=encrypted_fields)

