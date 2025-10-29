# encrypted_create_jsonSchema tries to create a collection with a non-trivial JSON schema.
import os
from pymongo import MongoClient
from pymongo.encryption_options import AutoEncryptionOpts

kms_providers = {"local": {"key": os.urandom(96)}}
key_vault_namespace = "keyvault.datakeys"

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
)
uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017")
client = MongoClient(uri, auto_encryption_opts=auto_encryption_opts)
client.db.create_collection("coll", validator={"$jsonSchema": {
    "bsonType": "object",
    "properties": {
        "foo": {"bsonType": "string"}
    },
    "required": ["foo"]
}}) # Error! "JSON schema keyword 'required' is only allowed with a remote schema"
