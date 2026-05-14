# To run:
#   export PYMONGOCRYPT_LIB=/path/to/libmongocrypt-1.18.1/lib/libmongocrypt.dylib
#   export CRYPT_SHARED_PATH=/path/to/mongo_crypt_v1.dylib
#   uv run test-auto-explicit-mix.py
#
# Regression test for DRIVERS-3470: libmongocrypt < 1.18.1 swapped caseSensitive
# and diacriticSensitive in explicit encryption, so auto-insert + explicit-find
# would return no results even for the correct string.
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

def make_clients(efm):
    auto_c = MongoClient(MONGODB_URI, auto_encryption_opts=AutoEncryptionOpts(
        kms_providers, key_vault_namespace, encrypted_fields_map=efm,
        crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
    ))
    explicit_c = MongoClient(MONGODB_URI, auto_encryption_opts=AutoEncryptionOpts(
        kms_providers, key_vault_namespace, encrypted_fields_map=efm,
        crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
        bypass_query_analysis=True,
    ))
    return auto_c, explicit_c

# ── Scenario A: auto-insert + explicit-find (cs=False ds=False) ───────────────
# The simplest DRIVERS-3470 regression: symmetric sensitivity flags.
print("Scenario A: auto-insert + explicit-find (caseSensitive=False, diacriticSensitive=False):")
efm_a = {"db.mixA": {"fields": [{"path": "secret", "bsonType": "string", "keyId": key_id,
    "queries": [{"queryType": "substringPreview", "strMinQueryLength": 2,
                 "strMaxQueryLength": 10, "strMaxLength": 20,
                 "caseSensitive": False, "diacriticSensitive": False, "contention": 0}]}]}}
OPTS_A = TextOpts(substring=SubstringOpts(strMinQueryLength=2, strMaxQueryLength=10, strMaxLength=20),
                  case_sensitive=False, diacritic_sensitive=False)
auto_a, explicit_a = make_clients(efm_a)
auto_a.db.drop_collection("mixA")
auto_a.db.create_collection("mixA")
auto_a.db.mixA.insert_one({"_id": 1, "secret": "foo"})

fp = client_encryption.encrypt("foo", algorithm="textPreview", query_type="substringPreview",
                               key_id=key_id, contention_factor=0, text_opts=OPTS_A)
check("explicit-find 'foo' after auto-insert 'foo' via $encStrContains → found",
      explicit_a.db.mixA, {"$encStrContains": {"input": "$secret", "substring": fp}}, True)

fp_upper = client_encryption.encrypt("FOO", algorithm="textPreview", query_type="substringPreview",
                                     key_id=key_id, contention_factor=0, text_opts=OPTS_A)
check("explicit-find 'FOO' after auto-insert 'foo' (caseSensitive=False) via $encStrContains → found",
      explicit_a.db.mixA, {"$encStrContains": {"input": "$secret", "substring": fp_upper}}, True)

# ── Scenario B: explicit-insert + auto-find ───────────────────────────────────
print("Scenario B: explicit-insert + auto-find (caseSensitive=False, diacriticSensitive=False):")
auto_a.db.drop_collection("mixA")
auto_a.db.create_collection("mixA")
insert_payload = client_encryption.encrypt(
    "foo", algorithm="textPreview", key_id=key_id, contention_factor=0, text_opts=OPTS_A)
explicit_a.db.mixA.insert_one({"_id": 1, "secret": insert_payload})

got = auto_a.db.mixA.find_one({"$expr": {"$encStrContains": {"input": "$secret", "substring": "foo"}}})
ok = bool(got)
status = "PASS" if ok else "FAIL"
if not ok:
    failures += 1
print(f"  [{status}] auto-find 'foo' after explicit-insert 'foo' via $encStrContains → found")

got = auto_a.db.mixA.find_one({"$expr": {"$encStrContains": {"input": "$secret", "substring": "FOO"}}})
ok = bool(got)
status = "PASS" if ok else "FAIL"
if not ok:
    failures += 1
print(f"  [{status}] auto-find 'FOO' after explicit-insert 'foo' (caseSensitive=False) via $encStrContains → found")

# ── Scenario C: auto-insert + explicit-find (cs=False ds=True) ────────────────
# The exact DRIVERS-3470 trigger: asymmetric sensitivity flags.
# Before the fix, caseSensitive and diacriticSensitive were swapped in explicit
# encryption, so explicit-find would use different tokens than auto-insert.
print("Scenario C: auto-insert + explicit-find (caseSensitive=False, diacriticSensitive=True):")
efm_c = {"db.mixC": {"fields": [{"path": "secret", "bsonType": "string", "keyId": key_id,
    "queries": [{"queryType": "substringPreview", "strMinQueryLength": 2,
                 "strMaxQueryLength": 10, "strMaxLength": 20,
                 "caseSensitive": False, "diacriticSensitive": True, "contention": 0}]}]}}
OPTS_C = TextOpts(substring=SubstringOpts(strMinQueryLength=2, strMaxQueryLength=10, strMaxLength=20),
                  case_sensitive=False, diacritic_sensitive=True)
auto_c, explicit_c = make_clients(efm_c)
auto_c.db.drop_collection("mixC")
auto_c.db.create_collection("mixC")
auto_c.db.mixC.insert_one({"_id": 1, "secret": "café"})

fp = client_encryption.encrypt("café", algorithm="textPreview", query_type="substringPreview",
                               key_id=key_id, contention_factor=0, text_opts=OPTS_C)
check("explicit-find 'café' after auto-insert 'café' (cs=False ds=True) → found",
      explicit_c.db.mixC, {"$encStrContains": {"input": "$secret", "substring": fp}}, True)

fp_upper = client_encryption.encrypt("CAFÉ", algorithm="textPreview", query_type="substringPreview",
                                     key_id=key_id, contention_factor=0, text_opts=OPTS_C)
check("explicit-find 'CAFÉ' after auto-insert 'café' (caseSensitive=False) → found",
      explicit_c.db.mixC, {"$encStrContains": {"input": "$secret", "substring": fp_upper}}, True)

fp_nodiac = client_encryption.encrypt("cafe", algorithm="textPreview", query_type="substringPreview",
                                      key_id=key_id, contention_factor=0, text_opts=OPTS_C)
check("explicit-find 'cafe' (no diacritic) after auto-insert 'café' (diacriticSensitive=True) → not found",
      explicit_c.db.mixC, {"$encStrContains": {"input": "$secret", "substring": fp_nodiac}}, False)

if failures:
    print(f"\n{failures} failure(s).")
    sys.exit(1)
