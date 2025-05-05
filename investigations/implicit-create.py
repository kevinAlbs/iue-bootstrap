"""
Q: Does QE implicitly create server-side collection (and schema)?
A:
"""

import os
from bson.codec_options import CodecOptions
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts

# Clear previous data:
unencrypted_client = MongoClient()
unencrypted_client.drop_database("db")

# Create data keys:
local_master_key = os.urandom(96)
kms_providers = {"local": {"key": local_master_key}}
client_encryption = ClientEncryption(
    kms_providers, "db.keyvault", unencrypted_client, CodecOptions()
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
db = client["db"]

print ("Inserting without creating collection ...")
coll = db["coll"]
coll.insert_one({"secret": "foo"}) # Implicitly creates db.coll.
# Inspect listCollections results:
collinfo = db.list_collections (filter={"name": "coll"}).next()
# encryptedFields is not implicitly addded:
assert "encryptedFields" not in collinfo["options"]
# esc/ecoc collections implicitly created:
assert db.list_collections (filter={"name": "enxcol_.coll.esc"}).try_next() is not None
assert db.list_collections (filter={"name": "enxcol_.coll.ecoc"}).try_next() is not None
print ("Inserting without creating collection ... done")

coll.drop()

print ("Inserting into db.coll after creating collection ...")
coll = client["db"].create_collection("coll") # Includes encryptedFields from auto_encryption_opts 
coll.insert_one({"secret": "foo"})
# Inspect listCollections results:
collinfo = db.list_collections (filter={"name": "coll"}).next()
assert "encryptedFields" in collinfo["options"] # Present
assert db.list_collections (filter={"name": "enxcol_.coll.esc"}).try_next() is not None
assert db.list_collections (filter={"name": "enxcol_.coll.ecoc"}).try_next() is not None
print ("Inserting without creating collection ... done")
print ("Inserting into db.coll after creating collection ... done")
