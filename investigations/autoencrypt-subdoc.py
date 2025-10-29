import os
from bson.codec_options import CodecOptions
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts

local_master_key = os.urandom(96)
kms_providers = {"local": {"key": local_master_key}}
key_vault_namespace = "keyvault.datakeys"
key_vault_client = MongoClient("mongodb://localhost:27777")
client_encryption = ClientEncryption(
    kms_providers, key_vault_namespace, key_vault_client, CodecOptions()
)
key_vault = key_vault_client["keyvault"]["datakeys"]
key_vault.drop()
key_id1 = client_encryption.create_data_key("local")
key_id2 = client_encryption.create_data_key("local")

encrypted_fields_map = {
    "db.coll": {
        "fields": [
            {
                "path": "patientRecord.ssn",
                "bsonType": "string",
                "queries": { "queryType": "equality" }, # This field IS SEARCHABLE
                "keyId": key_id1
            },
            {
                "path": "patientRecord.billing",
                "bsonType": "object", # This subdocument (and all child fields) is encrypted BUT NOT SEARCHABLE
                "keyId": key_id2
            },
        ],
    }
}

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
    encrypted_fields_map=encrypted_fields_map,
)
client = MongoClient("mongodb://localhost:27777", auto_encryption_opts=auto_encryption_opts)
client.db.drop_collection("coll")
coll = client.db.create_collection("coll")
coll.insert_one({"_id": 1, "patientRecord": {"ssn": "123-56-6789", "billing": {"card": "4111111111111111"}}})
docs = list(coll.find({}))
print(docs)

coll.insert_one({"_id": 2, "patientRecord": {"ssn": "123-56-6789", "billing": {"card": "4111111111111111", "name": "foo"}}})
