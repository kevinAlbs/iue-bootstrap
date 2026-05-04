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
from pymongo.encryption_options import AutoEncryptionOpts, TextOpts, PrefixOpts
from bson.json_util import dumps
from pathlib import Path


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


class CommandLogger(monitoring.CommandListener):
    def started(self, event):
        if event.command_name != "insert":
            return
        
        if "secret" not in event.command["documents"][0]:
            # Skip. May be be insert for key vault document.
            return
    
        auto_payload = event.command["documents"][0]["secret"]
        print("Auto encrypted insert payload:")
        print (dumps(auto_payload, indent=2))
        dump_FLE2InsertUpdatePayloadV2(auto_payload, "auto_payload.json")
            

    def succeeded(self, event):
        pass

    def failed(self, event):
        pass


monitoring.register(CommandLogger())

local_master_key = bytes.fromhex("327834342b786475546142426b593136457235447541446167687653347677646b67387470507033747a366756303141314377624439697451324846446750574f7038654d6143314f693736364a7a585a4264426462644d7572646f6e4a3164")
kms_providers = {"local": {"key": local_master_key}}
key_vault_namespace = "keyvault.datakeys"
key_vault_client = MongoClient()
client_encryption = ClientEncryption(
    kms_providers, key_vault_namespace, key_vault_client, CodecOptions()
)
key_vault = key_vault_client["keyvault"]["datakeys"]
key = key_vault.find_one({"keyAltNames": ["testKey"]})
if key is None:
    print ("Key not detected. Creating ...")
    key_id = client_encryption.create_data_key("local", key_alt_names=["testKey"])
else:
    print("Using key with _id:", key["_id"].hex())
    key_id = key["_id"]

encrypted_fields_map = {
    "db.coll": {
        "fields": [
            {
                "path": "secret",
                "bsonType": "string",
                "keyId": key_id,
                "queries": [
                    {
                        "queryType": "prefixPreview",
                        "strMinQueryLength": 2,
                        "strMaxQueryLength": 10,
                        "caseSensitive": True,
                        "diacriticSensitive": True,
                        "contention": 0,
                    }
                    # {
                    #     "queryType": "equality",
                    #     "contention": 0,
                    # }
                ]
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
client.db.drop_collection("coll")
coll = client.db.create_collection("coll")
coll.insert_one({"_id": 1, "secret": "foo"})

# Do explicit encryption:
explicit_payload = client_encryption.encrypt("foo", algorithm="textPreview", key_id=key_id, contention_factor=0, text_opts=TextOpts(prefix=PrefixOpts(strMinQueryLength=2, strMaxQueryLength=10), case_sensitive=True, diacritic_sensitive=True))
print("Explicit encrypted insert payload:")
print(dumps(explicit_payload, indent=2))
dump_FLE2InsertUpdatePayloadV2(explicit_payload, "explicit_payload.json")


print ("Dumped payloads to explicit_payload.json and auto_payload.json")
