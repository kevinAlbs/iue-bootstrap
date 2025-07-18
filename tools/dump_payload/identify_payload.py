import base64
import sys

if len(sys.argv) != 2:
    print("Usage: {} <base64 CSFLE/QE payload>".format(sys.argv[0]))
    sys.exit()

data = base64.b64decode(sys.argv[1])
blob_subtype = data[0]
blob_subtypes = {
    0: "FLE1EncryptionPlaceholder",
    1: "FLE1DeterministicEncryptedValue",
    2: "FLE1RandomEncryptedValue",
    3: "FLE2EncryptionPlaceholder",
    4: "FLE2InsertUpdatePayload",
    5: "FLE2FindEqualityPayload",
    6: "FLE2UnindexedEncryptedValue",
    7: "FLE2IndexedEqualityEncryptedValue",
    9: "FLE2IndexedRangeEncryptedValue",
    10: "FLE2FindRangePayload",
    11: "FLE2InsertUpdatePayloadV2",
    12: "FLE2FindEqualityPayloadV2",
    13: "FLE2FindRangePayloadV2",
    14: "FLE2EqualityIndexedValueV2",
    15: "FLE2RangeIndexedValueV2",
    16: "FLE2UnindexedEncryptedValueV2",
    17: "FLE2IndexedTextEncryptedValue",
    18: "FLE2FindTextPayload",
}

print ("Detected payload type: {}".format(blob_subtypes[blob_subtype]["name"]))
