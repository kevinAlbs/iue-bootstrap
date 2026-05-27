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
                "path": "secretSubstring",
                "keyId": key_id,
                "bsonType": "string",
                "queries": [
                    {
                        "bypassSubstringLimits": True, # [crypt_shared 9.0.0-alpha0-a406ebcf] "analyze_query" failed: BSON field 'EncryptedFieldConfig.fields.queries.bypassSubstringLimits' is an unknown field.
                        "queryType": "substringPreview",
                        "strMaxLength": 10,
                        "strMinQueryLength": 2,
                        "strMaxQueryLength": 10,
                        "caseSensitive": True,
                        "diacriticSensitive": True,
                    }
                ],
            }
        ],
    }
}

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
    encrypted_fields_map=encrypted_fields_map,
    crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
)
client = MongoClient(auto_encryption_opts=auto_encryption_opts)
client.db.drop_collection("coll")
coll = client.db.create_collection("coll")
coll.insert_one({"_id": 1, "secretSubstring": "bar"})
docs = list(coll.find({}))
print(docs)
