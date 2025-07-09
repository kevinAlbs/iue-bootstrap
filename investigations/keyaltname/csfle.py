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
key_id = client_encryption.create_data_key("local", key_alt_names=["foo"])


schema_map = {
    "db.coll": {
        "properties": {
            "secret": {
                "encrypt": {
                    # `keyId` is a JSON pointer. "key" fields refer to "keyAltName".
                    "keyId": "/key",
                    "bsonType": "string",
                    "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random",
                }
            }
        },
        "bsonType": "object",
    }
}

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers, key_vault_namespace, schema_map=schema_map
)
client = MongoClient(auto_encryption_opts=auto_encryption_opts)
client.db.drop_collection("coll")
coll = client.db.create_collection("coll")
coll.insert_one(
    {
        "_id": 1,
        "secret": "secret",
        "key": "foo",  # Requests key with keyAltName "foo"
    }
)
docs = list(coll.find({}))
print(docs)
