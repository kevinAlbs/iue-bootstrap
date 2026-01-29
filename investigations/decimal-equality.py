import os
from bson.codec_options import CodecOptions
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts
from bson.decimal128 import Decimal128

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
                "bsonType": "decimal",
                "keyId": key_id,
                # Decimal128 supports the "range" index, which supports equality queries.
                "queries": [{"queryType": "range", "min": Decimal128("0.0"), "max": Decimal128("100.0"), "precision": 2, "contention": 4, "sparsity": 2, }],
                # Decimal128 does NOT support the "equality" index. Example:
                # "queries": [{"queryType": "equality", "min": Decimal128("0.0"), "max": Decimal128("100.0"), "precision": 2, "contention": 4, "sparsity": 2, }],
                # Gets back: "Type 'decimal' is not a supported equality indexed type"
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
client = MongoClient(auto_encryption_opts=auto_encryption_opts)
client.db.drop_collection("coll")
coll = client.db.create_collection("coll")
coll.insert_one({"_id": 1, "secret": Decimal128("42.42")})

# Can find with a range query:
got = list(coll.find({"secret": { "$gt": Decimal128("40.00"), "$lt": Decimal128("50.00") }}))
assert(len(got) == 1 and got[0]["_id"] == 1)

# Can find with an equality query:
got = list(coll.find({"secret": Decimal128("42.42")}))
assert(len(got) == 1 and got[0]["_id"] == 1)

