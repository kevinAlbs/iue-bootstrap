"""
Create a QE collection with a local encryptedFields.
"""

from bson.codec_options import CodecOptions
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts
from pathlib import Path
from bson import json_util

local_master_key = Path("local-master-key-base64.txt").read_text()
kms_providers = {"local": {"key": local_master_key}}
key_vault_namespace = "keyvault.datakeys"

# Create collection if needed:
if not Path("db.coll-encryptedFields.json").exists():
    encrypted_fields_in = {
         "fields": [
            {
                "path": "firstName",
                "bsonType": "string",
                "keyId": None, # Request a new key in `create_encrypted_collection`.
                "queries": [{"queryType": "equality"}]
            },
            {
                "path": "lastName",
                "bsonType": "string",
                "keyId": None, # Request a new key in `create_encrypted_collection`.
            }
        ],
    }

    client = MongoClient()
    client_encryption = ClientEncryption(kms_providers, key_vault_namespace, client, CodecOptions())
    (_, encrypted_fields_out) = client_encryption.create_encrypted_collection (client["db"], "coll", encrypted_fields_in, kms_provider="local")
    # Store the resulting encryptedFields (containing the IDs of created keys):
    Path("db.coll-encryptedFields.json").write_text(json_util.dumps(encrypted_fields_out))

encrypted_fields_map = {
    "db.coll": json_util.loads(Path("db.coll-encryptedFields.json").read_text())
}

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
    encrypted_fields_map=encrypted_fields_map,
)
client = MongoClient(auto_encryption_opts=auto_encryption_opts)
coll = client["db"]["coll"]
coll.insert_one({"_id": 1, "firstName": "Jane", "lastName": "Doe"})
docs = list(coll.find({"firstName": "Jane"}))
print(docs)
