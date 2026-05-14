# To run:
#   export PYMONGOCRYPT_LIB=/path/to/libmongocrypt-1.18.1/lib/libmongocrypt.dylib
#   export CRYPT_SHARED_PATH=/path/to/mongo_crypt_v1.dylib
#   uv run test-operators.py
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

DOC_VALUE = "FooBarBaz"
failures = 0

def check(label, coll, query, expect_found):
    global failures
    got = coll.find_one({"$expr": query})
    ok = bool(got) == expect_found
    status = "PASS" if ok else "FAIL"
    if not ok:
        failures += 1
    print(f"  [{status}] {label}")

def make_clients(encrypted_fields_map):
    auto_client = MongoClient(MONGODB_URI, auto_encryption_opts=AutoEncryptionOpts(
        kms_providers, key_vault_namespace,
        encrypted_fields_map=encrypted_fields_map,
        crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
    ))
    explicit_client = MongoClient(MONGODB_URI, auto_encryption_opts=AutoEncryptionOpts(
        kms_providers, key_vault_namespace,
        encrypted_fields_map=encrypted_fields_map,
        crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
        bypass_query_analysis=True,
    ))
    return auto_client, explicit_client

# ── $encStrContains (substringPreview) ────────────────────────────────────────
print("$encStrContains:")
substr_efm = {
    "db.substringColl": {"fields": [{"path": "secret", "bsonType": "string", "keyId": key_id,
        "queries": [{"queryType": "substringPreview", "strMinQueryLength": 2,
                     "strMaxQueryLength": 10, "strMaxLength": 20,
                     "caseSensitive": False, "diacriticSensitive": False, "contention": 0}]}]}
}
auto_c, explicit_c = make_clients(substr_efm)
auto_c.db.drop_collection("substringColl")
auto_c.db.create_collection("substringColl")
coll = explicit_c.db.substringColl
substr_opts = TextOpts(substring=SubstringOpts(strMinQueryLength=2, strMaxQueryLength=10, strMaxLength=20),
                       case_sensitive=False, diacritic_sensitive=False)
coll.insert_one({"_id": 1, "secret": client_encryption.encrypt(
    DOC_VALUE, algorithm="textPreview", key_id=key_id, contention_factor=0, text_opts=substr_opts)})

for (search, expect) in [("ooBar", True), ("FooBar", True), ("xyz", False), ("fo", True)]:
    fp = client_encryption.encrypt(search, algorithm="textPreview", query_type="substringPreview",
                                   key_id=key_id, contention_factor=0, text_opts=substr_opts)
    check(f"  '{DOC_VALUE}' contains '{search}' → {'found' if expect else 'not found'}",
          coll, {"$encStrContains": {"input": "$secret", "substring": fp}}, expect)

# ── $encStrNormalizedEq (substringPreview, case-insensitive normalized eq) ────
print("$encStrNormalizedEq (via substringPreview):")
# $encStrNormalizedEq finds doc when the whole value normalizes to the query string.
for (search, expect) in [("foobarbaz", True), ("FooBarBaz", True), ("foo", False)]:
    fp = client_encryption.encrypt(search, algorithm="textPreview", query_type="substringPreview",
                                   key_id=key_id, contention_factor=0, text_opts=substr_opts)
    check(f"  normalizedEq '{DOC_VALUE}' == '{search}' → {'found' if expect else 'not found'}",
          coll, {"$encStrNormalizedEq": {"input": "$secret", "string": fp}}, expect)

# ── $encStrStartsWith (prefixPreview) ─────────────────────────────────────────
print("$encStrStartsWith:")
prefix_efm = {
    "db.prefixColl": {"fields": [{"path": "secret", "bsonType": "string", "keyId": key_id,
        "queries": [{"queryType": "prefixPreview", "strMinQueryLength": 2,
                     "strMaxQueryLength": 10, "strMaxLength": 20,
                     "caseSensitive": False, "diacriticSensitive": False, "contention": 0}]}]}
}
auto_c2, explicit_c2 = make_clients(prefix_efm)
auto_c2.db.drop_collection("prefixColl")
auto_c2.db.create_collection("prefixColl")
pcoll = explicit_c2.db.prefixColl
prefix_opts = TextOpts(prefix=PrefixOpts(strMinQueryLength=2, strMaxQueryLength=10),
                       case_sensitive=False, diacritic_sensitive=False)
pcoll.insert_one({"_id": 1, "secret": client_encryption.encrypt(
    DOC_VALUE, algorithm="textPreview", key_id=key_id, contention_factor=0, text_opts=prefix_opts)})

for (search, expect) in [("Foo", True), ("foo", True), ("FooBar", True), ("Bar", False), ("Baz", False)]:
    fp = client_encryption.encrypt(search, algorithm="textPreview", query_type="prefixPreview",
                                   key_id=key_id, contention_factor=0, text_opts=prefix_opts)
    check(f"  '{DOC_VALUE}' starts-with '{search}' → {'found' if expect else 'not found'}",
          pcoll, {"$encStrStartsWith": {"input": "$secret", "prefix": fp}}, expect)

# ── $encStrEndsWith (suffixPreview) ───────────────────────────────────────────
print("$encStrEndsWith:")
suffix_efm = {
    "db.suffixColl": {"fields": [{"path": "secret", "bsonType": "string", "keyId": key_id,
        "queries": [{"queryType": "suffixPreview", "strMinQueryLength": 2,
                     "strMaxQueryLength": 10, "strMaxLength": 20,
                     "caseSensitive": False, "diacriticSensitive": False, "contention": 0}]}]}
}
auto_c3, explicit_c3 = make_clients(suffix_efm)
auto_c3.db.drop_collection("suffixColl")
auto_c3.db.create_collection("suffixColl")
scoll = explicit_c3.db.suffixColl
suffix_opts = TextOpts(suffix=SuffixOpts(strMinQueryLength=2, strMaxQueryLength=10),
                       case_sensitive=False, diacritic_sensitive=False)
scoll.insert_one({"_id": 1, "secret": client_encryption.encrypt(
    DOC_VALUE, algorithm="textPreview", key_id=key_id, contention_factor=0, text_opts=suffix_opts)})

for (search, expect) in [("Baz", True), ("baz", True), ("BarBaz", True), ("Foo", False), ("Bar", False)]:
    fp = client_encryption.encrypt(search, algorithm="textPreview", query_type="suffixPreview",
                                   key_id=key_id, contention_factor=0, text_opts=suffix_opts)
    check(f"  '{DOC_VALUE}' ends-with '{search}' → {'found' if expect else 'not found'}",
          scoll, {"$encStrEndsWith": {"input": "$secret", "suffix": fp}}, expect)

if failures:
    print(f"\n{failures} failure(s).")
    sys.exit(1)
