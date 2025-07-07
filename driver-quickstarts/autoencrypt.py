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

# Create two keys:
key1_id = client_encryption.create_data_key("local")
key2_id = client_encryption.create_data_key("local")

encrypted_fields_map = {
    "db.coll": {
        "fields": [
            {
                "path": "firstName",
                "bsonType": "string",
                "keyId": key1_id,
                "queries": [{"queryType": "equality"}],
            },
            {
                "path": "lastName",
                "bsonType": "string",
                "keyId": key2_id,
            },
        ],
    }
}

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
    encrypted_fields_map=encrypted_fields_map,
)
client = MongoClient(auto_encryption_opts=auto_encryption_opts)
client.db.drop_collection("coll")
coll = client.db.create_collection("coll")
coll.insert_one({"_id": 1, "firstName": "Jane", "lastName": "Doe"})
docs = list(coll.find({"firstName": "Jane"}))
print(docs)
