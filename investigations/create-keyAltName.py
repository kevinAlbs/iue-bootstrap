# create-keyAltName tries to create a QE collection using "keyAltName" in "encryptedFields"
import os
from pymongo import MongoClient
from pymongo.encryption_options import AutoEncryptionOpts

kms_providers = {"local": {"key": os.urandom(96)}}
key_vault_namespace = "keyvault.datakeys"

local_master_key = os.urandom(96)
kms_providers = {"local": {"key": local_master_key}}
key_vault_namespace = "keyvault.datakeys"

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
)
uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017")

# Drop pre-existing data:
client = MongoClient(uri)
client.db.coll.drop()

# Try to create a QE collection with an unencrypted client:
encrypted_client = MongoClient(uri, auto_encryption_opts=auto_encryption_opts)
client.db.create_collection("coll", encrypted_fields={"fields": [
    {
        "path": "secret",
        "bsonType": "string",
        "keyAltName": "foo" # TODO: will this work with MONGOCRYPT-432?
    },
]})
