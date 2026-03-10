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


auto_encryption_opts = AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
    encrypted_fields_map={},
    crypt_shared_lib_path=os.environ["CRYPT_SHARED_PATH"],
)
client = MongoClient(auto_encryption_opts=auto_encryption_opts)
client.db.drop_collection("coll")
reply = client.db.command({
    "insert": "coll", # db.coll has no $jsonSchema or encryptedFields.
    "badField": "foo" # Error from crypt_shared: "analyze_query" failed: BSON field 'insert.badField' is an unknown field"
})
print(reply)
