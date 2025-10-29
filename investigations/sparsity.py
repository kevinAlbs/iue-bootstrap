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

encrypted_fields = {
    "fields": [
        {
            "keyId": key_id,
            "path": "qe_range",
            "bsonType": "int",
            "queries": {"queryType": "range", "min": 0, "max": 100, "contention": 0, "sparsity": 9},
        }
    ],
}

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
)
encrypted_client = MongoClient(auto_encryption_opts=auto_encryption_opts)
encrypted_client.drop_database("db")

coll = encrypted_client["db"].create_collection("coll", encryptedFields=encrypted_fields)
