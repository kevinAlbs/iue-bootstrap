# To run:
#   export PYMONGOCRYPT_LIB=/path/to/libmongocrypt-1.18.1/lib/libmongocrypt.dylib
#   export CRYPT_SHARED_PATH=/path/to/mongo_crypt_v1.dylib
#   uv run insert-find.py
#
# /// script
# dependencies = [
#   "pymongo[encryption]",
# ]
# ///

import os
import sys
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
if key is None:
    key_id = client_encryption.create_data_key("local", key_alt_names=["testKey"])
else:
    key_id = key["_id"]

encrypted_fields_map = {
    "db.coll": {
        "fields": [{
            "path": "secret",
            "bsonType": "string",
            "keyId": key_id,
            "queries": [{
                "queryType": "substringPreview",
                "strMinQueryLength": 2,
                "strMaxQueryLength": 10,
                "strMaxLength": 20,
                "caseSensitive": False,
                "diacriticSensitive": False,
                "contention": 0,
            }],
        }],
    }
}

# Create collection via auto-encrypting client (creates ESC/ECOC metadata collections).
auto_client = MongoClient(MONGODB_URI, auto_encryption_opts=AutoEncryptionOpts(
    kms_providers, key_vault_namespace,
    encrypted_fields_map=encrypted_fields_map,
    crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
))
auto_client.db.drop_collection("coll")
auto_client.db.create_collection("coll")

# Explicit client: bypasses query analysis; we supply payloads ourselves.
explicit_client = MongoClient(MONGODB_URI, auto_encryption_opts=AutoEncryptionOpts(
    kms_providers, key_vault_namespace,
    encrypted_fields_map=encrypted_fields_map,
    crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
    bypass_query_analysis=True,
))
explicit_coll = explicit_client["db"]["coll"]

OPTS = TextOpts(
    substring=SubstringOpts(strMinQueryLength=2, strMaxQueryLength=10, strMaxLength=20),
    case_sensitive=False,
    diacritic_sensitive=False,
)

# Insert document with explicit encryption (no query_type for insert).
insert_payload = client_encryption.encrypt(
    value="FooBarBaz",
    algorithm="textPreview",
    key_id=key_id,
    contention_factor=0,
    text_opts=OPTS,
)
explicit_coll.insert_one({"_id": 1, "secret": insert_payload})

failures = 0

def check(label, coll, query, expect_found):
    global failures
    got = coll.find_one({"$expr": query})
    ok = bool(got) == expect_found
    status = "PASS" if ok else "FAIL"
    if not ok:
        failures += 1
    print(f"  [{status}] {label}")

# Positive: "ooBar" is contained in "FooBarBaz".
find_payload = client_encryption.encrypt(
    value="ooBar", algorithm="textPreview", query_type="substringPreview",
    key_id=key_id, contention_factor=0, text_opts=OPTS,
)
check(
    "$encStrContains 'ooBar' in 'FooBarBaz' → found",
    explicit_coll,
    {"$encStrContains": {"input": "$secret", "substring": find_payload}},
    expect_found=True,
)

# Negative: "xyz" is not in "FooBarBaz".
find_payload = client_encryption.encrypt(
    value="xyz", algorithm="textPreview", query_type="substringPreview",
    key_id=key_id, contention_factor=0, text_opts=OPTS,
)
check(
    "$encStrContains 'xyz' in 'FooBarBaz' → not found",
    explicit_coll,
    {"$encStrContains": {"input": "$secret", "substring": find_payload}},
    expect_found=False,
)

if failures:
    print(f"\n{failures} failure(s).")
    sys.exit(1)
