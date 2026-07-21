# Run with: uv
#
# /// script
# dependencies = [
#   "pymongo[encryption]",
# ]
# ///

import datetime
import os
import struct

from bson.binary import Binary
from bson.codec_options import CodecOptions
from bson.code import Code
from bson.decimal128 import Decimal128
from bson.int64 import Int64
from bson.max_key import MaxKey
from bson.min_key import MinKey
from bson.objectid import ObjectId
from bson.raw_bson import RawBSONDocument
from bson.regex import Regex
from bson.timestamp import Timestamp
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

# Every BSON type alias name from:
# https://www.mongodb.com/docs/manual/reference/bson-types/
bson_types = [
    "double",
    "string",
    "object",
    "array",
    "binData",
    "undefined",
    "objectId",
    "bool",
    "date",
    "null",
    "regex",
    "dbPointer",
    "javascript",
    "symbol",
    "javascriptWithScope",
    "int",
    "timestamp",
    "long",
    "decimal",
    "minKey",
    "maxKey",
]


def _bson_string(s):
    b = s.encode("utf-8") + b"\x00"
    return struct.pack("<i", len(b)) + b


def _raw_doc(secret_type_byte, secret_value):
    """Hand-build {"_id": 1, "secret": <value>} with an arbitrary BSON type
    byte for "secret", for deprecated types pymongo can't natively construct."""
    elements = b"\x10_id\x00" + struct.pack("<i", 1)  # int32 _id
    elements += secret_type_byte + b"secret\x00" + secret_value
    body = elements + b"\x00"
    return RawBSONDocument(struct.pack("<i", len(body) + 4) + body)


# A real BSON symbol (0x0E): a string payload, but a distinct type from string.
_symbol_doc = _raw_doc(b"\x0e", _bson_string("sym"))
# A real BSON dbPointer (0x0C): namespace string followed by a 12-byte ObjectId.
_dbpointer_doc = _raw_doc(b"\x0c", _bson_string("db.coll") + ObjectId().binary)

# A sample value matching each bsonType, so the insert exercises the actual
# type rather than always inserting a string.
sample_values = {
    "double": 1.5,
    "string": "foo",
    "object": {"a": 1},
    "array": [1, 2, 3],
    "binData": Binary(b"data", 0),
    "undefined": None,  # no distinct Python type; create_collection fails first
    "objectId": ObjectId(),
    "bool": True,
    "date": datetime.datetime(2026, 1, 1),
    "null": None,
    "regex": Regex("^foo", "i"),
    "javascript": Code("function () {}"),
    "javascriptWithScope": Code("function () {}", {"x": 1}),
    "int": 42,
    "timestamp": Timestamp(1, 1),
    "long": Int64(1 << 40),
    "decimal": Decimal128("1.5"),
    "minKey": MinKey(),
    "maxKey": MaxKey(),
}

# Deprecated types with no native pymongo constructor: insert a hand-built doc.
sample_docs = {
    "symbol": _symbol_doc,
    "dbPointer": _dbpointer_doc,
}

results = {}
for bson_type in bson_types:
    encrypted_fields_map = {
        "db.coll": {
            "fields": [
                {
                    "path": "secret",
                    "bsonType": bson_type,
                    "keyId": key_id,
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
    client = MongoClient(auto_encryption_opts=auto_encryption_opts)
    try:
        client.db.drop_collection("coll")
        coll = client.db.create_collection("coll")
        doc = sample_docs.get(bson_type, {"_id": 1, "secret": sample_values.get(bson_type)})
        coll.insert_one(doc)
        results[bson_type] = "OK (create + insert)"
    except Exception as e:
        # Prefer the short server errmsg over the full raw-BSON dump.
        msg = str(e).split(", full error:")[0]
        results[bson_type] = f"ERROR: {msg}"
    finally:
        client.close()

print("Results (bsonType -> outcome of create_collection + insert):")
for bson_type in bson_types:
    print(f"  {bson_type:22} {results[bson_type]}")
