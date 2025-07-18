import base64
import bson
import bson.json_util
import sys

if len(sys.argv) != 2:
    print("Usage: {} <base64 CSFLE/QE payload>".format(sys.argv[0]))
    sys.exit()

data = base64.b64decode(sys.argv[1])
blob_subtype = data[0]

blob_subtypes = {
    0: {"name": "FLE1EncryptionPlaceholder", "isBSON": True},
    1: {"name": "FLE1DeterministicEncryptedValue", "isBSON": False},
    2: {"name": "FLE1RandomEncryptedValue", "isBSON": False},
    3: {"name": "FLE2EncryptionPlaceholder", "isBSON": True},
    4: {"name": "FLE2InsertUpdatePayload", "isBSON": True},
    5: {"name": "FLE2FindEqualityPayload", "isBSON": True},
    6: {"name": "FLE2UnindexedEncryptedValue", "isBSON": False},
    7: {"name": "FLE2IndexedEqualityEncryptedValue", "isBSON": False},
    9: {"name": "FLE2IndexedRangeEncryptedValue", "isBSON": False},
    10: {"name": "FLE2FindRangePayload", "isBSON": True},
    11: {"name": "FLE2InsertUpdatePayloadV2", "isBSON": True},
    12: {"name": "FLE2FindEqualityPayloadV2", "isBSON": True},
    13: {"name": "FLE2FindRangePayloadV2", "isBSON": True},
    14: {"name": "FLE2EqualityIndexedValueV2", "isBSON": False},
    15: {"name": "FLE2RangeIndexedValueV2", "isBSON": False},
    16: {"name": "FLE2UnindexedEncryptedValueV2", "isBSON": False},
    17: {"name": "FLE2IndexedTextEncryptedValue", "isBSON": False},
    18: {"name": "FLE2FindTextPayload", "isBSON": False},
}

if blob_subtype not in blob_subtypes.keys():
    print("Do not know how to parse blob subtype: {}".format(blob_subtype))
    sys.exit()


print ("Detected payload type: {}".format(blob_subtypes[blob_subtype]["name"]))

if blob_subtypes[blob_subtype]["isBSON"]:
    # If data is represented as BSON, print BSON
    as_bson = bson.decode (data[1:])
    as_ejson = bson.json_util.dumps(as_bson, indent=4)
    print ("{}".format(as_ejson))

