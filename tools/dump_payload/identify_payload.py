import base64
import sys
import bson
import bson.json_util
import bson.errors
import argparse

parser = argparse.ArgumentParser(description="Usage: {} <base64 CSFLE/QE payload>".format(sys.argv[0])) 
parser.add_argument(  
    '--no-bson',  
    action='store_true',  
    help='Disable printing BSON (if applicable)'
)  

parser.add_argument(  
    'base64',
    type=str,
    help='base64 of a CSFLE/QE payload'  
)  

args = parser.parse_args()  

data = base64.b64decode(args.base64)
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

print ("Detected payload type: {}".format(blob_subtypes[blob_subtype]))

# Some payloads are light wrappers around BSON.
if not args.no_bson:
    try:
        as_bson = bson.decode(data[1:])
        print(bson.json_util.dumps(as_bson, indent=4))
    except bson.errors.InvalidBSON:
        # Ignore.
        pass
