# To run:
#
#   export CRYPT_SHARED_PATH=/path/to/mongo_crypt_v1.dylib
#   export MONGODB_URI="mongodb://localhost:27017"
#   uv run two_clients.py
#
#
# Sample output:
#
#    Auto encrypted client can decrypt data:
#    {'_id': 1, 'secret': 'foo'}
#    Regular client cannot decrypt data:
#    {'_id': 1, 'secret': Binary(b'\x10\xa6\x04\x17\x8d\xa1\xc4O\x90\xbf\x80B\x93\xf4\xa3\x89\x1f\x02\x04\xab\xf6\xb6\xb7\x98I\x93"\xa2[W-\xe4-\xbcb!e{\xfaBf\x0055\xdf\xb4,\xa0\xa4\xaa\t\xe7\xe4\xe3\xd5}^\xceq\xfcn\xcasE\x84hz#\xf9ZN\xd8I\xa4\x0b\xbf\x18\x07g\x05\x94\xb4', 6)}
#
#
# /// script
# dependencies = [
#   "pymongo[encryption]",
# ]
# ///

import os
from bson.codec_options import CodecOptions
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts

local_master_key = os.urandom(96)
kms_providers = {"local": {"key": local_master_key}}
key_vault_namespace = "keyvault.datakeys"
key_vault_client = MongoClient()
client_encryption = ClientEncryption(
    kms_providers, key_vault_namespace, key_vault_client, CodecOptions()
)
key_vault = key_vault_client["keyvault"]["datakeys"]
key_vault.drop()
key_id = client_encryption.create_data_key("local")

encrypted_fields_map = {
    "db.coll": {
        "fields": [
            {
                "path": "secret",
                "bsonType": "string",
                "keyId": key_id,
            },
        ],
    }
}

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
    encrypted_fields_map=encrypted_fields_map,
    crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
)
auto_encrypted_client = MongoClient(os.environ.get("MONGODB_URI"), auto_encryption_opts=auto_encryption_opts)
auto_encrypted_client.db.drop_collection("coll")
coll = auto_encrypted_client.db.create_collection("coll")
coll.insert_one({"_id": 1, "secret": "foo"})


print ("Auto encrypted client can decrypt data:")
print(next(coll.find({})))

regular_client = MongoClient()
coll = regular_client.db["coll"]
print ("Regular client cannot decrypt data:")
print(next(coll.find({})))
