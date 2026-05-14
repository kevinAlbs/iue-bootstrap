# Isolated reproduction of possible bug: $encStrNormalizedEq on a substringPreview
# index finds documents where the query is a substring of the value, not just where
# the query equals the whole value.
#
# Expected behavior: $encStrNormalizedEq "foo" should NOT find "FooBarBaz" because
# "foo" != "FooBarBaz" (even after case normalization).
#
# Observed behavior: it does find "FooBarBaz", suggesting the operator is matching
# against stored substring tokens rather than a whole-value equality token.
#
# Two tests to isolate whether this is a client-side (explicit encrypt) or
# server-side bug:
#   Test 1: auto-insert, explicit-find  → already observed: "foo" finds "FooBarBaz"
#   Test 2: auto-insert, auto-find      → if also true, the bug is server-side
#
# To run:
#   export PYMONGOCRYPT_LIB=/path/to/libmongocrypt-1.18.1/lib/libmongocrypt.dylib
#   export CRYPT_SHARED_PATH=/path/to/mongo_crypt_v1.dylib
#   uv run test-normalizedeq-bug.py
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

MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb://localhost:27017")
kms_providers = {"local": {"key": bytes.fromhex(
    "327834342b786475546142426b593136457235447541446167687653347677646b67387470507033747a366756303141314377624439697451324846446750574f7038654d6143314f693736364a7a585a4264426462644d7572646f6e4a3164"
)}}
key_vault_namespace = "keyvault.datakeys"
key_vault_client = MongoClient(MONGODB_URI)
client_encryption = ClientEncryption(kms_providers, key_vault_namespace, key_vault_client, CodecOptions())
key_vault = key_vault_client["keyvault"]["datakeys"]
key = key_vault.find_one({"keyAltNames": ["testKey"]})
key_id = key["_id"] if key else client_encryption.create_data_key("local", key_alt_names=["testKey"])

efm = {"db.neqBug": {"fields": [{"path": "secret", "bsonType": "string", "keyId": key_id,
    "queries": [{"queryType": "substringPreview", "strMinQueryLength": 2,
                 "strMaxQueryLength": 10, "strMaxLength": 20,
                 "caseSensitive": False, "diacriticSensitive": False, "contention": 0}]}]}}
OPTS = TextOpts(substring=SubstringOpts(strMinQueryLength=2, strMaxQueryLength=10, strMaxLength=20),
                case_sensitive=False, diacritic_sensitive=False)

auto_client = MongoClient(MONGODB_URI, auto_encryption_opts=AutoEncryptionOpts(
    kms_providers, key_vault_namespace, encrypted_fields_map=efm,
    crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
))
explicit_client = MongoClient(MONGODB_URI, auto_encryption_opts=AutoEncryptionOpts(
    kms_providers, key_vault_namespace, encrypted_fields_map=efm,
    crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
    bypass_query_analysis=True,
))

auto_client.db.drop_collection("neqBug")
auto_client.db.create_collection("neqBug")
auto_client.db.neqBug.insert_one({"_id": 1, "secret": "FooBarBaz"})

print("Document inserted: 'FooBarBaz' (auto-encrypted, substringPreview, caseSensitive=False)")
print()

# Test 1: auto-insert, explicit-find
print("Test 1: explicit-find via $encStrNormalizedEq")
for query_str in ["foobarbaz", "FooBarBaz", "foo", "foobar", "oob"]:
    fp = client_encryption.encrypt(query_str, algorithm="textPreview", query_type="substringPreview",
                                   key_id=key_id, contention_factor=0, text_opts=OPTS)
    found = bool(explicit_client.db.neqBug.find_one(
        {"$expr": {"$encStrNormalizedEq": {"input": "$secret", "string": fp}}}))
    print(f"  $encStrNormalizedEq '{query_str}': {'found' if found else 'not found'}")

print()

# Test 2: auto-insert, auto-find
print("Test 2: auto-find via $encStrNormalizedEq")
for query_str in ["foobarbaz", "FooBarBaz", "foo", "foobar", "oob"]:
    found = bool(auto_client.db.neqBug.find_one(
        {"$expr": {"$encStrNormalizedEq": {"input": "$secret", "string": query_str}}}))
    print(f"  $encStrNormalizedEq '{query_str}': {'found' if found else 'not found'}")
