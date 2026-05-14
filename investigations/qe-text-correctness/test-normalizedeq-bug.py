# Isolated reproduction of possible bug: $encStrNormalizedEq finds documents where
# the query is a substring/prefix/suffix of the value, not just where the query equals
# the whole value.
#
# Expected behavior: $encStrNormalizedEq "foo" should NOT find "FooBarBaz" because
# "foo" != "FooBarBaz" (even after case normalization).
#
# Observed behavior (substringPreview): explicit-find returns found for "foo", "foobar",
# "oob" — partial substrings of "FooBarBaz". Auto-find correctly returns not found for
# those. This isolates the bug to libmongocrypt's explicit encrypt path generating a
# substring/prefix/suffix token instead of an exact-match token.
#
# This file also tests prefixPreview and suffixPreview to check whether libmongocrypt
# has the same bug there — hypothesis: it's using the index-type token (prefix/suffix)
# instead of the exact token regardless of which index type is used.
#
# Two tests per index type:
#   Test 1: auto-insert, explicit-find
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
from pymongo.encryption_options import AutoEncryptionOpts, TextOpts, SubstringOpts, PrefixOpts, SuffixOpts

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

# ── prefixPreview ─────────────────────────────────────────────────────────────
print()
print("=== prefixPreview ===")
print("Document inserted: 'FooBarBaz' (auto-encrypted, prefixPreview, caseSensitive=False)")
print()

efm_p = {"db.neqBugPrefix": {"fields": [{"path": "secret", "bsonType": "string", "keyId": key_id,
    "queries": [{"queryType": "prefixPreview", "strMinQueryLength": 2,
                 "strMaxQueryLength": 10, "strMaxLength": 20,
                 "caseSensitive": False, "diacriticSensitive": False, "contention": 0}]}]}}
OPTS_P = TextOpts(prefix=PrefixOpts(strMinQueryLength=2, strMaxQueryLength=10),
                  case_sensitive=False, diacritic_sensitive=False)

auto_p = MongoClient(MONGODB_URI, auto_encryption_opts=AutoEncryptionOpts(
    kms_providers, key_vault_namespace, encrypted_fields_map=efm_p,
    crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
))
explicit_p = MongoClient(MONGODB_URI, auto_encryption_opts=AutoEncryptionOpts(
    kms_providers, key_vault_namespace, encrypted_fields_map=efm_p,
    crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
    bypass_query_analysis=True,
))
auto_p.db.drop_collection("neqBugPrefix")
auto_p.db.create_collection("neqBugPrefix")
auto_p.db.neqBugPrefix.insert_one({"_id": 1, "secret": "FooBarBaz"})

# "Foo" and "FooBar" are valid prefixes; "foobarbaz" is the full value; "oob" and "Baz" are not prefixes.
print("Test 1: explicit-find via $encStrNormalizedEq")
for query_str in ["foobarbaz", "FooBarBaz", "foo", "foobar", "oob", "baz"]:
    fp = client_encryption.encrypt(query_str, algorithm="textPreview", query_type="prefixPreview",
                                   key_id=key_id, contention_factor=0, text_opts=OPTS_P)
    found = bool(explicit_p.db.neqBugPrefix.find_one(
        {"$expr": {"$encStrNormalizedEq": {"input": "$secret", "string": fp}}}))
    print(f"  $encStrNormalizedEq '{query_str}': {'found' if found else 'not found'}")

print()
print("Test 2: auto-find via $encStrNormalizedEq")
for query_str in ["foobarbaz", "FooBarBaz", "foo", "foobar", "oob", "baz"]:
    found = bool(auto_p.db.neqBugPrefix.find_one(
        {"$expr": {"$encStrNormalizedEq": {"input": "$secret", "string": query_str}}}))
    print(f"  $encStrNormalizedEq '{query_str}': {'found' if found else 'not found'}")

# ── suffixPreview ─────────────────────────────────────────────────────────────
print()
print("=== suffixPreview ===")
print("Document inserted: 'FooBarBaz' (auto-encrypted, suffixPreview, caseSensitive=False)")
print()

efm_s = {"db.neqBugSuffix": {"fields": [{"path": "secret", "bsonType": "string", "keyId": key_id,
    "queries": [{"queryType": "suffixPreview", "strMinQueryLength": 2,
                 "strMaxQueryLength": 10, "strMaxLength": 20,
                 "caseSensitive": False, "diacriticSensitive": False, "contention": 0}]}]}}
OPTS_S = TextOpts(suffix=SuffixOpts(strMinQueryLength=2, strMaxQueryLength=10),
                  case_sensitive=False, diacritic_sensitive=False)

auto_s = MongoClient(MONGODB_URI, auto_encryption_opts=AutoEncryptionOpts(
    kms_providers, key_vault_namespace, encrypted_fields_map=efm_s,
    crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
))
explicit_s = MongoClient(MONGODB_URI, auto_encryption_opts=AutoEncryptionOpts(
    kms_providers, key_vault_namespace, encrypted_fields_map=efm_s,
    crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
    bypass_query_analysis=True,
))
auto_s.db.drop_collection("neqBugSuffix")
auto_s.db.create_collection("neqBugSuffix")
auto_s.db.neqBugSuffix.insert_one({"_id": 1, "secret": "FooBarBaz"})

# "Baz" and "BarBaz" are valid suffixes; "foobarbaz" is the full value; "foo" and "oob" are not suffixes.
print("Test 1: explicit-find via $encStrNormalizedEq")
for query_str in ["foobarbaz", "FooBarBaz", "baz", "barbaz", "oob", "foo"]:
    fp = client_encryption.encrypt(query_str, algorithm="textPreview", query_type="suffixPreview",
                                   key_id=key_id, contention_factor=0, text_opts=OPTS_S)
    found = bool(explicit_s.db.neqBugSuffix.find_one(
        {"$expr": {"$encStrNormalizedEq": {"input": "$secret", "string": fp}}}))
    print(f"  $encStrNormalizedEq '{query_str}': {'found' if found else 'not found'}")

print()
print("Test 2: auto-find via $encStrNormalizedEq")
for query_str in ["foobarbaz", "FooBarBaz", "baz", "barbaz", "oob", "foo"]:
    found = bool(auto_s.db.neqBugSuffix.find_one(
        {"$expr": {"$encStrNormalizedEq": {"input": "$secret", "string": query_str}}}))
    print(f"  $encStrNormalizedEq '{query_str}': {'found' if found else 'not found'}")
