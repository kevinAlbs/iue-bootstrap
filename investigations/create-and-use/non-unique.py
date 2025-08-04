"""
Create a QE collection with a local encryptedFields.
"""

from bson.codec_options import CodecOptions
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts
import os

local_master_key = os.urandom(96)
kms_providers = {"local": {"key": local_master_key}}
key_vault_namespace = "keyvault.datakeys"

client = MongoClient()
client.drop_database("db") # Clear pre-existing data.
client_encryption = ClientEncryption(kms_providers, key_vault_namespace, client, CodecOptions())
key1_id = client_encryption.create_data_key("local")
key2_id = client_encryption.create_data_key("local")
encrypted_fields = {
    "fields": [
        {
            "path": "firstName",
            "bsonType": "string",
            "keyId": key1_id,
            "queries": [{"queryType": "equality"}]
        },
        {
            "path": "lastName",
            "bsonType": "string",
            "keyId": key1_id,
        }
    ],
}

encrypted_fields_map = {
    "db.coll": encrypted_fields
}

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
    encrypted_fields_map=encrypted_fields_map,
)
client = MongoClient(auto_encryption_opts=auto_encryption_opts)
client.db.drop_collection("coll")
coll = client.db.create_collection("coll") # Error: Duplicate key ids are not allowed!
coll.insert_one({"_id": 1, "firstName": "Jane", "lastName": "Doe"})
docs = list(coll.find({"firstName": "Jane"}))
print(docs)
