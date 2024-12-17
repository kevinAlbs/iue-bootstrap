import os
from bson.codec_options import CodecOptions
from pymongo import MongoClient
from pymongo.encryption import Algorithm, ClientEncryption, QueryType
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
# Ensure that two data keys cannot share the same keyAltName.
key_vault.create_index(
    "keyAltNames",
    unique=True,
    partialFilterExpression={"keyAltNames": {"$exists": True}},
)
key1_id = client_encryption.create_data_key("local", key_alt_names=["firstName"])
key2_id = client_encryption.create_data_key("local", key_alt_names=["lastName"])

encrypted_fields_map = {
    "default.encryptedCollection": {
        "fields": [
            {
                "path": "foo",
                "bsonType": "int",
                "keyId": key1_id,
                "queries": [{"queryType": "range", "min": 0, "max": 100}],
            }
        ],
    }
}

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
    encrypted_fields_map=encrypted_fields_map,
)
client = MongoClient(auto_encryption_opts=auto_encryption_opts)
client.default.drop_collection("encryptedCollection")
coll = client.default.create_collection("encryptedCollection")
coll.insert_one({"_id": 1, "foo": 101 })
docs = list(coll.find({"foo": 101}))
print(docs)
