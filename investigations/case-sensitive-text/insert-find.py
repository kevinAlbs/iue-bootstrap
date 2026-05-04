# To run:
#   export CRYPT_SHARED_PATH=/path/to/crypt_shared.dylib
#   uv run insert-find.py
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
from pymongo.encryption_options import AutoEncryptionOpts, TextOpts, SubstringOpts

kms_providers = {"local": {"key": bytes.fromhex("327834342b786475546142426b593136457235447541446167687653347677646b67387470507033747a366756303141314377624439697451324846446750574f7038654d6143314f693736364a7a585a4264426462644d7572646f6e4a3164")}}
key_vault_namespace = "keyvault.datakeys"
key_vault_client = MongoClient()
client_encryption = ClientEncryption(
    kms_providers, key_vault_namespace, key_vault_client, CodecOptions()
)

# Create or reuse Data Encryption Key (DEK):
key_vault = key_vault_client["keyvault"]["datakeys"]
key = key_vault.find_one({"keyAltNames": ["testKey"]})
if key is None:
    print ("Key not detected. Creating ...")
    key_id = client_encryption.create_data_key("local", key_alt_names=["testKey"])
else:
    print("Using key with _id:", key["_id"].hex())
    key_id = key["_id"]

# Insert with auto-encryption:
print ("Inserting auto-encrypted 'foo' with 'substringPreview' ...")
encrypted_fields_map = {
    "db.coll": {
        "fields": [
            {
                "path": "secret",
                "bsonType": "string",
                "keyId": key_id,
                "queries": [
                    {
                        "queryType": "substringPreview",
                        "strMinQueryLength": 2,
                        "strMaxQueryLength": 10,
                        "strMaxLength": 10,
                        "caseSensitive": False,
                        "diacriticSensitive": False,
                        "contention": 0,
                    }
                ]
            },
        ],
    }
}
client = MongoClient(auto_encryption_opts=AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
    encrypted_fields_map=encrypted_fields_map,
    crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
))
client.db.drop_collection("coll")
coll = client.db.create_collection("coll")
coll.insert_one({"_id": 1, "secret": "foo"})
print ("Inserting auto-encrypted 'foo' with 'substringPreview' ... done")

# Find with explicit-encryption:
client_explicit = MongoClient(auto_encryption_opts=AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
    encrypted_fields_map=encrypted_fields_map,
    crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
    bypass_query_analysis=True # No auto encryption
))

print ("Finding 'foo' with '$encStrNormalizedEq' ...")
explicit_payload = client_encryption.encrypt("foo", algorithm="textPreview", query_type="substringPreview", key_id=key_id, contention_factor=0, text_opts=TextOpts(substring=SubstringOpts(strMinQueryLength=2, strMaxQueryLength=10, strMaxLength=10), case_sensitive=False, diacritic_sensitive=False))
got = client_explicit["db"]["coll"].find_one({ "$expr": { "$encStrNormalizedEq": {"input": "$secret", "string": explicit_payload} } })
if got:
    print ("Finding 'foo' with '$encStrNormalizedEq' ... found")
else:
    print ("Finding 'foo' with '$encStrNormalizedEq' ... NOT FOUND!")

print ("Finding 'FOO' with '$encStrNormalizedEq' ...")
explicit_payload = client_encryption.encrypt("FOO", algorithm="textPreview", query_type="substringPreview", key_id=key_id, contention_factor=0, text_opts=TextOpts(substring=SubstringOpts(strMinQueryLength=2, strMaxQueryLength=10, strMaxLength=10), case_sensitive=False, diacritic_sensitive=False))
got = client_explicit["db"]["coll"].find_one({ "$expr": { "$encStrNormalizedEq": {"input": "$secret", "string": explicit_payload} } })
if got:
    print ("Finding 'FOO' with '$encStrNormalizedEq' ... found")
else:
    print ("Finding 'FOO' with '$encStrNormalizedEq' ... NOT FOUND!")
