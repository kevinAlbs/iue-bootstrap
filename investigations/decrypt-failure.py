"""
Q: Does QE error on failure to decrypt?
A: Yes. "not all keys requested were satisfied"
"""

import os
from bson.codec_options import CodecOptions
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts

# Clear previous data:
keyvault_client = MongoClient()
keyvault_client.drop_database("db")

# Create data key:
local_master_key = os.urandom(96)
kms_providers = {"local": {"key": local_master_key}}
client_encryption = ClientEncryption(
    kms_providers, "db.keyvault", keyvault_client, CodecOptions()
)
key_id = client_encryption.create_data_key("local")

encrypted_fields_map = {
    "db.coll": {
        "fields": [
            {
                "path": "secret",
                "bsonType": "string",
                "keyId": key_id,
                "queries": [{"queryType": "equality"}] # queries require esc/ecoc collections
            }
        ],
    }
}

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers,
    "db.keyvault",
    encrypted_fields_map=encrypted_fields_map,
)
client = MongoClient(auto_encryption_opts=auto_encryption_opts)
client["db"].create_collection("coll")
client["db"]["coll"].insert_one({"secret": "foo"})
client.close()

# Delete DEK.
keyvault_client["db"]["keyvault"].delete_one({"_id": key_id})

# Create new client to clear Data Encryption Key (DEK) cache.
client = MongoClient(auto_encryption_opts=auto_encryption_opts)
try:
    print(client["db"]["coll"].find_one({}))
except Exception as exc:
    print ("Exception: {}".format(exc))
# Exception: not all keys requested were satisfied. Verify that key vault DB/collection name was correctly specified.
