# To run:
#   export PYMONGOCRYPT_LIB=/path/to/libmongocrypt-1.18.1/lib/libmongocrypt.dylib
#   export CRYPT_SHARED_PATH=/path/to/mongo_crypt_v1.dylib
#   uv run test-sensitivity.py
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
key_id = key["_id"] if key else client_encryption.create_data_key("local", key_alt_names=["testKey"])

failures = 0

def check(label, coll, query, expect_found):
    global failures
    got = coll.find_one({"$expr": query})
    ok = bool(got) == expect_found
    status = "PASS" if ok else "FAIL"
    if not ok:
        failures += 1
    print(f"  [{status}] {label}")

def make_collection(coll_name, case_sensitive, diacritic_sensitive):
    efm = {
        f"db.{coll_name}": {"fields": [{"path": "secret", "bsonType": "string", "keyId": key_id,
            "queries": [{"queryType": "substringPreview", "strMinQueryLength": 2,
                         "strMaxQueryLength": 10, "strMaxLength": 20,
                         "caseSensitive": case_sensitive,
                         "diacriticSensitive": diacritic_sensitive,
                         "contention": 0}]}]}
    }
    auto_c = MongoClient(MONGODB_URI, auto_encryption_opts=AutoEncryptionOpts(
        kms_providers, key_vault_namespace, encrypted_fields_map=efm,
        crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
    ))
    explicit_c = MongoClient(MONGODB_URI, auto_encryption_opts=AutoEncryptionOpts(
        kms_providers, key_vault_namespace, encrypted_fields_map=efm,
        crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
        bypass_query_analysis=True,
    ))
    auto_c.db.drop_collection(coll_name)
    auto_c.db.create_collection(coll_name)
    return explicit_c.db[coll_name], TextOpts(
        substring=SubstringOpts(strMinQueryLength=2, strMaxQueryLength=10, strMaxLength=20),
        case_sensitive=case_sensitive,
        diacritic_sensitive=diacritic_sensitive,
    )

def insert_doc(coll, value, opts):
    payload = client_encryption.encrypt(
        value, algorithm="textPreview", key_id=key_id, contention_factor=0, text_opts=opts)
    coll.delete_many({})
    coll.insert_one({"_id": 1, "secret": payload})

def make_find_payload(value, opts):
    return client_encryption.encrypt(
        value, algorithm="textPreview", query_type="substringPreview",
        key_id=key_id, contention_factor=0, text_opts=opts)

# ── caseSensitive=False, diacriticSensitive=False ─────────────────────────────
print("caseSensitive=False, diacriticSensitive=False:")
coll, opts = make_collection("sens_ff", case_sensitive=False, diacritic_sensitive=False)
insert_doc(coll, "foo", opts)
check("find 'foo' in 'foo' → found",    coll, {"$encStrContains": {"input": "$secret", "substring": make_find_payload("foo", opts)}}, True)
check("find 'FOO' in 'foo' → found",    coll, {"$encStrContains": {"input": "$secret", "substring": make_find_payload("FOO", opts)}}, True)
check("find 'bar' in 'foo' → not found",coll, {"$encStrContains": {"input": "$secret", "substring": make_find_payload("bar", opts)}}, False)
insert_doc(coll, "café", opts)
check("find 'cafe' in 'café' → found",  coll, {"$encStrContains": {"input": "$secret", "substring": make_find_payload("cafe", opts)}}, True)
check("find 'CAFE' in 'café' → found",  coll, {"$encStrContains": {"input": "$secret", "substring": make_find_payload("CAFE", opts)}}, True)

# ── caseSensitive=True, diacriticSensitive=True ───────────────────────────────
print("caseSensitive=True, diacriticSensitive=True:")
coll, opts = make_collection("sens_tt", case_sensitive=True, diacritic_sensitive=True)
insert_doc(coll, "foo", opts)
check("find 'foo' in 'foo' → found",    coll, {"$encStrContains": {"input": "$secret", "substring": make_find_payload("foo", opts)}}, True)
check("find 'FOO' in 'foo' → not found",coll, {"$encStrContains": {"input": "$secret", "substring": make_find_payload("FOO", opts)}}, False)
insert_doc(coll, "café", opts)
check("find 'café' in 'café' → found",  coll, {"$encStrContains": {"input": "$secret", "substring": make_find_payload("café", opts)}}, True)
check("find 'cafe' in 'café' → not found",coll,{"$encStrContains": {"input": "$secret", "substring": make_find_payload("cafe", opts)}},False)

# ── caseSensitive=True, diacriticSensitive=False ──────────────────────────────
print("caseSensitive=True, diacriticSensitive=False:")
coll, opts = make_collection("sens_tf", case_sensitive=True, diacritic_sensitive=False)
insert_doc(coll, "café", opts)
check("find 'cafe' in 'café' → found",  coll, {"$encStrContains": {"input": "$secret", "substring": make_find_payload("cafe", opts)}}, True)
check("find 'CAFE' in 'café' → not found",coll,{"$encStrContains": {"input": "$secret", "substring": make_find_payload("CAFE", opts)}},False)

# ── caseSensitive=False, diacriticSensitive=True ──────────────────────────────
print("caseSensitive=False, diacriticSensitive=True:")
coll, opts = make_collection("sens_ft", case_sensitive=False, diacritic_sensitive=True)
insert_doc(coll, "café", opts)
check("find 'CAFÉ' in 'café' → found",  coll, {"$encStrContains": {"input": "$secret", "substring": make_find_payload("CAFÉ", opts)}}, True)
check("find 'cafe' in 'café' → not found",coll,{"$encStrContains": {"input": "$secret", "substring": make_find_payload("cafe", opts)}},False)

if failures:
    print(f"\n{failures} failure(s).")
    sys.exit(1)
