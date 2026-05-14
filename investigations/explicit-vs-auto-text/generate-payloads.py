# /// script
# dependencies = [
#   "pymongo[encryption]",
# ]
# ///

import os
import bson
from bson.codec_options import CodecOptions
from pymongo import MongoClient, monitoring
from pymongo.encryption import ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts, TextOpts, SubstringOpts
from bson.json_util import dumps
from pathlib import Path

import pymongocrypt
print("Using libmongocrypt version:", pymongocrypt.libmongocrypt_version())

def dump_FLE2InsertUpdatePayloadV2(payload, filepath):
    """
    Dump an FLE2InsertUpdatePayloadV2.
    See https://github.com/mongodb/mongo/blob/b24400ba145db61b70145f6e3fcdc0508732cd7e/src/mongo/crypto/fle_field_schema.idl#L212
    for a description of the BSON fields.
    """

    payload = payload[1:]

    as_bson = bson.decode(payload)

    key_map = {
        "d": "EDCDerivedFromDataTokenAndCounter",
        "s": "ESCDerivedFromDataTokenAndCounter",
        "c": "ECCDerivedFromDataTokenAndCounter",
        "p": "Encrypted tokens",
        "u": "IndexKeyId",
        "t": "Encrypted type",
        "v": "Encrypted value",
        "e": "ServerDataEncryptionLevel1Token",
        "l": "ServerDerivedFromDataToken",
        "k": "ContentionFactor",
        "g": "EdgeTokenSet",
        "sp": "Sparsity",
        "pn": "Precision",
        "tf": "TrimFactor",
        "mn": "IndexMin",
        "mx": "IndexMax",
        "b": "TextSearchTokenSets"
    }

    annotated = {}
    for k, v in as_bson.items():
        if k in key_map:
            annotated["{} ({})".format(k, key_map[k])] = v

    Path(filepath).write_text(dumps(annotated, indent=2))

    print("b.e.d: {}".format(as_bson["b"]["e"]["d"].hex()))

file_suffix = ""

class MonitorForAutoEncryption(monitoring.CommandListener):
    def __init__(self):
        self.dumped = False

    def started(self, event):
        global file_suffix

        if event.command_name != "insert":
            return

        auto_payload = event.command["documents"][0]["secret"]
        dump_FLE2InsertUpdatePayloadV2(auto_payload, f"results/auto_insert_payload_{file_suffix}.json")

    def succeeded(self, event):
        pass

    def failed(self, event):
        pass


local_master_key = bytes.fromhex("327834342b786475546142426b593136457235447541446167687653347677646b67387470507033747a366756303141314377624439697451324846446750574f7038654d6143314f693736364a7a585a4264426462644d7572646f6e4a3164")
kms_providers = {"local": {"key": local_master_key}}
key_vault_namespace = "keyvault.datakeys"
key_vault_client = MongoClient(os.environ.get("MONGODB_URI", "mongodb://localhost:27017"))
client_encryption = ClientEncryption(
    kms_providers, key_vault_namespace, key_vault_client, CodecOptions()
)
key_vault = key_vault_client["keyvault"]["datakeys"]
key = key_vault.find_one({"keyAltNames": ["testKey"]})
if key is None:
    print("Key not detected. Creating ...")
    key_id = client_encryption.create_data_key("local", key_alt_names=["testKey"])
else:
    print("Using key with _id:", key["_id"].hex())
    key_id = key["_id"]
print()

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
                        "strMaxLength": 20,
                        "caseSensitive": False,
                        "diacriticSensitive": False,
                        "contention": 0,
                    }
                ],
            },
        ],
    }
}

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
    encrypted_fields_map=encrypted_fields_map,
    crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
)
client = MongoClient(
    os.environ.get("MONGODB_URI", "mongodb://localhost:27017"),
    auto_encryption_opts=auto_encryption_opts,
    event_listeners=[MonitorForAutoEncryption()],
)
client.db.drop_collection("coll")
coll = client.db.create_collection("coll")

# Insert and find with auto encryption:
plaintext="FOO"
file_suffix="upper"
coll.delete_many({}) # Delete prior data.
desc=f"Inserting '{plaintext}' with auto encryption ... "
print (desc)
coll.insert_one({"_id": 1, "secret": plaintext, "case": plaintext})
if coll.find_one({"$expr": {"$encStrContains": {"input": "$secret", "substring": plaintext}}}):
    print(desc + "OK")
else:
    print(desc + "NOT FOUND!")
print()

plaintext="foo"
file_suffix="lower"
desc=f"Inserting '{plaintext}' with auto encryption ... "
coll.delete_many({}) # Delete prior data.
print (desc)
coll.insert_one({"_id": 1, "secret": plaintext, "case": plaintext})
if coll.find_one({"$expr": {"$encStrContains": {"input": "$secret", "substring": plaintext}}}):
    print (desc + "OK")
else:
    print (desc + "NOT FOUND!")
print()

# Insert and find with explicit encryption:
explicit_auto_encryption_opts = AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
    encrypted_fields_map=encrypted_fields_map,
    crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
    bypass_query_analysis=True, # Use bypassQueryAnalysis=True
)
explicit_client = MongoClient(
    os.environ.get("MONGODB_URI", "mongodb://localhost:27017"),
    auto_encryption_opts=explicit_auto_encryption_opts,
)
explicit_coll = explicit_client.db.coll

plaintext="FOO"
file_suffix="upper"
coll.delete_many({}) # Delete prior data.
explicit_insert_payload = client_encryption.encrypt(value=plaintext, algorithm="textPreview", key_id=key_id, contention_factor=0, text_opts=TextOpts(substring=SubstringOpts(strMinQueryLength=2, strMaxQueryLength=10, strMaxLength=20), case_sensitive=False, diacritic_sensitive=False))
explicit_query_payload = client_encryption.encrypt(value=plaintext, query_type="substringPreview", algorithm="textPreview", key_id=key_id, contention_factor=0, text_opts=TextOpts(substring=SubstringOpts(strMinQueryLength=2, strMaxQueryLength=10, strMaxLength=20), case_sensitive=False, diacritic_sensitive=False))
explicit_coll.insert_one({"secret": explicit_insert_payload})
desc=f"Inserting '{plaintext}' with explicit encryption ... "
print (desc)
dump_FLE2InsertUpdatePayloadV2(explicit_insert_payload, f"results/explicit_insert_payload_{file_suffix}.json")
if explicit_coll.find_one({"$expr": { "$encStrContains": { "input": "$secret", "substring": explicit_query_payload }}}):
    print (desc + "OK")
else:
    print (desc + "NOT FOUND!")
print()

plaintext="foo"
file_suffix="lower"
coll.delete_many({}) # Delete prior data.
explicit_insert_payload = client_encryption.encrypt(value=plaintext, algorithm="textPreview", key_id=key_id, contention_factor=0, text_opts=TextOpts(substring=SubstringOpts(strMinQueryLength=2, strMaxQueryLength=10, strMaxLength=20), case_sensitive=False, diacritic_sensitive=False))
explicit_query_payload = client_encryption.encrypt(value=plaintext, query_type="substringPreview", algorithm="textPreview", key_id=key_id, contention_factor=0, text_opts=TextOpts(substring=SubstringOpts(strMinQueryLength=2, strMaxQueryLength=10, strMaxLength=20), case_sensitive=False, diacritic_sensitive=False))
explicit_coll.insert_one({"secret": explicit_insert_payload})
desc=f"Inserting '{plaintext}' with explicit encryption ... "
print (desc)
dump_FLE2InsertUpdatePayloadV2(explicit_insert_payload, f"results/explicit_insert_payload_{file_suffix}.json")
if explicit_coll.find_one({"$expr": { "$encStrContains": { "input": "$secret", "substring": explicit_query_payload }}}):
    print (desc + "OK")
else:
    print (desc + "NOT FOUND!")
print()

print("Dumped payloads to results/")
