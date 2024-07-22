"""
Dump In-Use Encryption payloads to text.

In-Use Encryption consists of Client-Side Field Level Encryption and Queryable Encryption.
In-Use Encryption makes use of the BSON binary subtype 6 in its protocol.

Example usage:
$ dump_payload.py ADgAAAAQYQABAAAABWtpABAAAAAEYWFhYWFhYWFhYWFhYWFhYQJ2AAwAAAA0NTctNTUtNTQ2MgAA
blob_subtype: 0 (FLE1EncryptionPlaceholder)
a (algorithm): 1 (Deterministic)
ki (keyId): b'aaaaaaaaaaaaaaaa' 
v (value): 457-55-5462
"""
import struct
import fle2_crypto
import argparse
import base64
import bson


def blob_subtype_to_string(blob_subtype):
    if blob_subtype == 0:
        return "FLE1EncryptionPlaceholder"
    elif blob_subtype == 1:
        return "FLE1DeterministicEncryptedValue"
    elif blob_subtype == 2:
        return "FLE1RandomEncryptedValue"
    elif blob_subtype == 3:
        return "FLE2EncryptionPlaceholder"
    elif blob_subtype == 4:
        return "FLE2InsertUpdatePayload"
    elif blob_subtype == 5:
        return "FLE2FindEqualityPayload"
    elif blob_subtype == 6:
        return "FLE2UnindexedEncryptedValue"
    elif blob_subtype == 7:
        return "FLE2IndexedEqualityEncryptedValue"
    elif blob_subtype == 9:
        return "FLE2IndexedRangeEncryptedValue"
    elif blob_subtype == 10:
        return "FLE2FindRangePayload"
    elif blob_subtype == 11:
        return "FLE2InsertUpdatePayloadV2"
    elif blob_subtype == 12:
        return "FLE2FindEqualityPayloadV2"
    elif blob_subtype == 13:
        return "FLE2FindRangePayloadV2"
    elif blob_subtype == 14:
        return "FLE2EqualityIndexedValueV2"
    elif blob_subtype == 15:
        return "FLE2RangeIndexedValueV2"
    elif blob_subtype == 16:
        return "FLE2UnindexedEncryptedValueV2"
    else:
        raise RuntimeError(
            "{} has no string name. Please add one.".format(blob_subtype))


def fle1_algorithm_to_string(algorithm):
    if algorithm == 1:
        return "Deterministic"
    if algorithm == 2:
        return "Random"
    raise RuntimeError("Unexpected FLE1 algorithm: {}".format(algorithm))


def fle2_algorithm_to_string(algorithm):
    if algorithm == 1:
        return "Unindexed"
    if algorithm == 2:
        return "Indexed Equality"
    if algorithm == 3:
        return "Indexed Range"
    raise RuntimeError("Unexpected FLE2 algorithm: {}".format(algorithm))


def fle2_type_to_string(type):
    if type == 1:
        return "kInsert"
    if type == 2:
        return "kFind"
    raise RuntimeError("Unexpected FLE2 type: {}".format(type))


def bson_type_to_string(bson_type):
    if bson_type == 1:
        return "double"
    if bson_type == 2:
        return "string"
    if bson_type == 3:
        return "object"
    if bson_type == 4:
        return "array"
    if bson_type == 5:
        return "binData"
    if bson_type == 6:
        return "undefined"
    if bson_type == 7:
        return "objectId"
    if bson_type == 8:
        return "bool"
    if bson_type == 9:
        return "date"
    if bson_type == 10:
        return "null"
    if bson_type == 11:
        return "regex"
    if bson_type == 12:
        return "dbPointer"
    if bson_type == 13:
        return "javascript"
    if bson_type == 14:
        return "symbol"
    if bson_type == 15:
        return "javascriptWithScope"
    if bson_type == 16:
        return "int"
    if bson_type == 17:
        return "timestamp"
    if bson_type == 18:
        return "long"
    if bson_type == 19:
        return "decimal"
    if bson_type == 20:
        return "minKey"
    if bson_type == 21:
        return "maxKey"
    raise RuntimeError("{} has no bson type string".format(bson_type))


def dump_payload1or2(payload):
    """
    Dump an FLE1RandomEncryptedValue or FLE1DeterministicEncryptedValue.
    See https://github.com/mongodb/specifications/blob/3634d568587a776f18885502cde4f26f1c0ac051/source/client-side-encryption/subtype6.rst#types-1-and-2-ciphertext
    for a description of the byte layout.
    """
    blob_subtype = payload[0]
    print("blob_subtype: {} ({})".format(
        blob_subtype, blob_subtype_to_string(blob_subtype)))
    payload = payload[1:]

    key_uuid = payload[0:16]
    print("key_uuid: {}".format(key_uuid.hex()))
    payload = payload[16:]

    original_bson_type = payload[0]
    print("original_bson_type: {} ({})".format(
        original_bson_type, bson_type_to_string(original_bson_type)))
    payload = payload[1:]

    ciphertext = payload[:]
    print("ciphertext: {}".format(ciphertext.hex()))


def dump_payload0(payload):
    """
    Dump an FLE1EncryptionPlaceholder.
    See https://github.com/mongodb/specifications/blob/3634d568587a776f18885502cde4f26f1c0ac051/source/client-side-encryption/subtype6.rst#type-0-intent-to-encrypt-marking
    for a description of the byte layout.
    """
    blob_subtype = payload[0]
    print("blob_subtype: {} ({})".format(
        blob_subtype, blob_subtype_to_string(blob_subtype)))
    payload = payload[1:]

    as_bson = bson.decode(payload)
    key_map = {
        "v": "value",
        "a": "algorithm",
        "ki": "keyId",
        "ka": "keyAltName"
    }

    for k, v in as_bson.items():
        suffix = ""
        if k == "a":
            suffix = "({})".format(fle1_algorithm_to_string(v))
        print("{} ({}): {} {}".format(k, key_map[k], v, suffix))


def dump_payload3(payload):
    """
    Dump an FLE2EncryptionPlaceholder.
    See https://github.com/mongodb/mongo/blob/a17007e3c4ecfd2e7a211ff9d98673dd37d87d0f/src/mongo/crypto/fle_field_schema.idl#L142
    for a description of the BSON fields.
    """
    blob_subtype = payload[0]
    print("blob_subtype: {} ({})".format(
        payload[0], blob_subtype_to_string(blob_subtype)))
    payload = payload[1:]

    as_bson = bson.decode(payload)
    key_map = {
        "t": "type",
        "a": "algorithm",
        "ku": "UserKeyId",
        "ki": "IndexKeyId",
        "v": "value",
        "cm": "max contention counter",
        "s": "sparsity"
    }

    for k, v in as_bson.items():
        suffix = ""
        if k == "a":
            suffix = "({})".format(fle2_algorithm_to_string(v))
        if k == "t":
            suffix = "({})".format(fle2_type_to_string(v))
        print("{} ({}): {} {}".format(k, key_map[k], v, suffix))


def do_dumpivs(ivs):
    print("IV data:")
    for iv in ivs:
        print("\"", end="")
        for b in iv:
            print("\\x{:02x}".format(b), end="")
        print("\"", end="")
        print(" \\")


def dump_payload4(payload, dumpivs=False):
    """
    Dump an FLE2InsertUpdatePayload.
    See https://github.com/mongodb/mongo/blob/a17007e3c4ecfd2e7a211ff9d98673dd37d87d0f/src/mongo/crypto/fle_field_schema.idl#L201
    for a description of the BSON fields.
    """
    ivs = []

    blob_subtype = payload[0]
    print("blob_subtype: {} ({})".format(
        payload[0], blob_subtype_to_string(blob_subtype)))
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
        "g": "EdgeTokenSet"
    }

    for k, v in as_bson.items():
        suffix = ""
        if dumpivs:
            if k == "p":
                # p : Encrypt(ECOCToken, ESCDerivedFromDataTokenAndCounter || ECCDerivedFromDataTokenAndCounter).
                # The IV is the first 16 bytes.
                ivs.append(v[0:16])
            elif k == "v":
                # v : UserKeyId + EncryptAEAD(K_KeyId, value)
                ivs.append(v[16:32])
        if type(v) == bytes:
            v = v.hex()
        if k == "g":
            print("{} ({}):".format(k, key_map[k], v, suffix))
            # This is an array of EdgeTokenSet.
            for i, EdgeTokenSet in enumerate(v):
                print("  token: {}".format(i))
                for ek, ev in EdgeTokenSet.items():
                    if dumpivs:
                        if ek == "p":
                            ivs.append(ev[0:16])
                    if type(ev) == bytes:
                        ev = ev.hex()
                    print("    {} ({}): {}".format(ek, key_map[ek], ev))
            continue
        print("{} ({}): {} {}".format(k, key_map[k], v, suffix))

    if dumpivs:
        do_dumpivs(ivs)


def dump_payload5(payload):
    """
    Dump an FLE2FindEqualityPayload.
    See https://github.com/mongodb/mongo/blob/a17007e3c4ecfd2e7a211ff9d98673dd37d87d0f/src/mongo/crypto/fle_field_schema.idl#L256
    for a description of the BSON fields.
    """
    blob_subtype = payload[0]
    print("blob_subtype: {} ({})".format(
        payload[0], blob_subtype_to_string(blob_subtype)))

    payload = payload[1:]
    as_bson = bson.decode(payload)
    key_map = {
        "d": "EDCDerivedFromDataToken",
        "s": "ESCDerivedFromDataToken",
        "c": "ECCDerivedFromDataToken",
        "cm": "FLE2 max counter",
        "e": "ServerDataEncryptionLevel1Token"
    }

    for k, v in as_bson.items():
        suffix = ""
        if type(v) == bytes:
            v = v.hex()
        print("{} ({}): {} {}".format(k, key_map[k], v, suffix))


def dump_payload6(payload):
    """
    Dump an FLE2UnindexedEncryptedValue.
    See https://github.com/mongodb/libmongocrypt/blob/66cec2c721c4f658b30fdaf2a4c844397feccffe/src/mc-fle2-payload-uev-private.h#L24
    for a description of the layout.
    """
    blob_subtype = payload[0]
    print("blob_subtype: {} ({})".format(
        payload[0], blob_subtype_to_string(blob_subtype)))
    payload = payload[1:]
    keyid = payload[0:16]
    payload = payload[16:]
    original_bson_type = payload[0]
    payload = payload[1:]
    ciphertext = payload
    print("key_uuid={}".format(keyid.hex()))
    print("original_bson_type={} ({})".format(
        original_bson_type, bson_type_to_string(original_bson_type)))
    print("ciphertext={}".format(ciphertext.hex()))


def dump_payload7(payload):
    """
    Dump an FLE2IndexedEqualityEncryptedValue.
    See https://github.com/mongodb/libmongocrypt/blob/66cec2c721c4f658b30fdaf2a4c844397feccffe/src/mc-fle2-payload-iev-private.h#L37-L65
    for a description of the layout.
    """
    blob_subtype = payload[0]
    print("blob_subtype: {} ({})".format(
        payload[0], blob_subtype_to_string(blob_subtype)))
    payload = payload[1:]
    S_KeyId = payload[0:16]
    payload = payload[16:]
    original_bson_type = payload[0]
    payload = payload[1:]
    InnerEncrypted = payload[1:]

    print("S_KeyId={}".format(S_KeyId.hex()))
    print("original_bson_type={}".format(
        original_bson_type, bson_type_to_string(original_bson_type)))
    print("InnerEncrypted={}".format(InnerEncrypted.hex()))


def _dump_FLE2FindRangePayloadEdgesInfo_g(g):
    key_map = {
        "d": "EDCDerivedFromDataToken",
        "s": "ESCDerivedFromDataToken",
        "c": "ECCDerivedFromDataToken",
    }

    # This is an array of EdgeTokenSet.
    for i, EdgeFindTokenSet in enumerate(g):
        print("    token: {}".format(i))
        for ek, ev in EdgeFindTokenSet.items():

            if type(ev) == bytes:
                ev = ev.hex()
            print("      {} ({}): {}".format(ek, key_map[ek], ev))


def _dump_FLE2FindRangePayloadEdgesInfo(payload):
    for k, v in payload.items():
        key_map = {
            "cm": "Queryable Encryption max counter",
            "e": "ServerDataEncryptionLevel1Token",
            "g": "array<EdgeFindTokenSet>"
        }
        if k == "g":
            print("  {} ({}):".format(k, key_map[k]))
            _dump_FLE2FindRangePayloadEdgesInfo_g(v)
            continue
        if type(v) == bytes:
            v = v.hex()
        print("  {} ({}): {}".format(k, key_map[k], v))


def dump_payload10(payload):
    """
    Dump an FLE2FindRangePayload.
    See https://github.com/mongodb/mongo/blob/a17007e3c4ecfd2e7a211ff9d98673dd37d87d0f/src/mongo/crypto/fle_field_schema.idl#L317-L336
    for a description of the BSON fields.
    """
    blob_subtype = payload[0]
    print("blob_subtype: {} ({})".format(
        payload[0], blob_subtype_to_string(blob_subtype)))
    payload = payload[1:]

    operatorMap = {
        1: "$gt",
        2: "$gte",
        3: "$lt",
        4: "$lte"
    }

    as_bson = bson.decode(payload)
    key_map = {
        "payload": "Token information for a find range payload",
        "payloadId": "Id of payload - must be paired with another payload",
        "firstOperator": "First query operator for which this payload was generated.",
        "secondOperator": "Second query operator for which this payload was generated. Only populated for two-sided ranges."
    }

    for k, v in as_bson.items():
        if type(v) == bytes:
            v = v.hex()
        if k == "payload":
            if k in ["firstOperator", "secondOperator"]:
                print("{} ({} ({})):".format(
                    k, key_map[k], operatorMap[key_map[k]]))
            else:
                print("{} ({}):".format(k, key_map[k]))
            _dump_FLE2FindRangePayloadEdgesInfo(v)
            continue
        print("{} ({}): {}".format(k, key_map[k], v))


def dump_payload9(payload, decrypt=False):
    """
    Dump an FLE2IndexedRangeEncryptedValue.
    See https://github.com/mongodb/libmongocrypt/blob/66cec2c721c4f658b30fdaf2a4c844397feccffe/src/mc-fle2-payload-iev-private.h#L67-L83
    for a description of the layout.
    """
    blob_subtype = payload[0]
    print("blob_subtype: {} ({})".format(
        payload[0], blob_subtype_to_string(blob_subtype)))
    payload = payload[1:]
    key_uuid = payload[0:16]
    payload = payload[16:]
    original_bson_type = payload[0]
    payload = payload[1:]
    InnerEncrypted = payload

    print("key_uuid={}".format(key_uuid.hex()))
    print("original_bson_type={}".format(
        original_bson_type, bson_type_to_string(original_bson_type)))
    print("InnerEncrypted={}".format(InnerEncrypted.hex()))

    if decrypt:
        print("Attempting to decrypt InnerEncrypted")
        dek = fle2_crypto.DEK.from_hexfile(
            "keys/{}-key-material.txt".format(key_uuid.hex().upper()))
        sdel1t = fle2_crypto.ServerDataEncryptionLevel1Token(dek.TokenKey)
        print("ServerDataEncryptionLevel1Token = {}".format(sdel1t.hex()))
        Inner = fle2_crypto.fle2_decrypt(InnerEncrypted, sdel1t)
        (length,) = struct.unpack("<q", Inner[0:8])
        print("Inner.length = {}".format(length))
        Inner = Inner[8:]
        K_KeyId = Inner[0:16]
        Inner = Inner[16:]
        print("Inner.K_KeyId = {}".format(K_KeyId.hex()))
        Inner_dek = fle2_crypto.DEK.from_hexfile(
            "keys/{}-key-material.txt".format(K_KeyId.hex().upper()))
        Inner_ClientEncryptedValue = Inner[0:(length - 16)]
        Inner = Inner[(length - 16):]
        ClientValue = fle2_crypto.fle2aead_decrypt(
            Inner_ClientEncryptedValue, Inner_dek.Km, K_KeyId, Inner_dek.Ke)
        print("ClientValue = {}".format(ClientValue.hex()))
        (edgeCount,) = struct.unpack("<I", Inner[0:4])
        Inner = Inner[4:]
        print("edgeCount={}".format(edgeCount))
        for i in range(edgeCount):
            print("edge {}".format(i))
            (counter,) = struct.unpack("<Q", Inner[0:8])
            print(" counter={}".format(counter))
            Inner = Inner[8:]
            edc = Inner[0:32]
            print(" edc={}".format(edc.hex()))
            Inner = Inner[32:]
            esc = Inner[0:32]
            print(" esc={}".format(esc.hex()))
            Inner = Inner[32:]
            ecc = Inner[0:32]
            print(" ecc={}".format(ecc.hex()))
            Inner = Inner[32:]
        if len(Inner) > 0:
            raise RuntimeError(
                "unexpected extra bytes: {}".format(Inner.hex()))
        
def dump_payload11(payload, dumpivs=False):
    """
    Dump an FLE2InsertUpdatePayloadV2.
    See https://github.com/mongodb/mongo/blob/b24400ba145db61b70145f6e3fcdc0508732cd7e/src/mongo/crypto/fle_field_schema.idl#L212
    for a description of the BSON fields.
    """
    ivs = []

    blob_subtype = payload[0]
    print("blob_subtype: {} ({})".format(
        payload[0], blob_subtype_to_string(blob_subtype)))
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
        "mx": "IndexMax"
    }

    for k, v in as_bson.items():
        suffix = ""
        if type(v) == bytes:
            v = v.hex()
        if k == "g":
            print("{} ({}):".format(k, key_map[k], v, suffix))
            # This is an array of EdgeTokenSet.
            for i, EdgeTokenSet in enumerate(v):
                print("  token: {}".format(i))
                for ek, ev in EdgeTokenSet.items():
                    if dumpivs:
                        if ek == "p":
                            ivs.append(ev[0:16])
                    if type(ev) == bytes:
                        ev = ev.hex()
                    print("    {} ({}): {}".format(ek, key_map[ek], ev))
            continue
        print("{} ({}): {} {}".format(k, key_map[k], v, suffix))


def dump_payload13(payload):
    """
    Dump an FLE2FindRangePayloadV2.
    See https://github.com/mongodb/mongo/blob/c675b7164d26faa943f7ff576b3be102a239d927/src/mongo/crypto/fle_field_schema.idl#L339-L386
    for a description of the BSON fields.
    """

    blob_subtype = payload[0]
    print("blob_subtype: {} ({})".format(
        payload[0], blob_subtype_to_string(blob_subtype)))
    payload = payload[1:]

    as_bson = bson.decode(payload)
    key_map = {
        "payload": "payload",
        "payloadId": "payloadId",
        "firstOperator": "firstOperator",
        "secondOperator": "secondOperator",
        "sp": "sparsity",
        "pn": "precision",
        "tf": "trimFactor",
        "mn": "indexMin",
        "mx": "indexMax",
        "cm": "maxCounter"
    }

    for k, v in as_bson.items():
        if type(v) is bytes:
            v = v.hex()
        if k == "payload":
            print("{} ({}):".format(k, key_map[k]))
            for pk, pv in v.items():
                if pk == "g":
                    print ("{}: ({} edges)".format(pk, len(pv)))
                else:
                    print("{} ({}): {}".format(pk, key_map[pk], pv))
            continue
        print("{} ({}): {}".format(k, key_map[k], v))



def infer_base64_or_hex(input: str, encoding):
    """
    infer_base64_or_hex decodes input as hex or base64.
    If both decodings are valid, hex is preferred.
    The decoding may be chosen with encoding.
    """

    if encoding == "base64":
        return base64.b64decode(input)
    elif encoding == "hex":
        return bytes.fromhex(input)
    elif encoding != "unknown":
        raise RuntimeError("unexpected encoding: {}".format(encoding))

    try:
        return bytes.fromhex(input)
    except ValueError as ve:
        pass

    return base64.b64decode(input)


def dump_payload(input: str, encoding="unknown", decrypt=False, dumpivs=False):
    payload = infer_base64_or_hex(input, encoding)
    supports_decrypt = False
    supports_dumpivs = False
    if payload[0] == 1 or payload[0] == 2:
        dump_payload1or2(payload)
    elif payload[0] == 0:
        dump_payload0(payload)
    elif payload[0] == 3:
        dump_payload3(payload)
    elif payload[0] == 4:
        supports_dumpivs = True
        dump_payload4(payload, dumpivs=dumpivs)
    elif payload[0] == 5:
        dump_payload5(payload)
    elif payload[0] == 6:
        dump_payload6(payload)
    elif payload[0] == 7:
        dump_payload7(payload)
    elif payload[0] == 10:
        dump_payload10(payload)
    elif payload[0] == 9:
        supports_decrypt = True
        dump_payload9(payload, decrypt=decrypt)
    elif payload[0] == 11:
        dump_payload11(payload)
    elif payload[0] == 12:
        print("Got payload type: {}. Do not know how to decode.".format(
            blob_subtype_to_string(payload[0])))
    elif payload[0] == 13:
        dump_payload13(payload)
    elif payload[0] == 14:
        print("Got payload type: {}. Do not know how to decode.".format(
            blob_subtype_to_string(payload[0])))
    elif payload[0] == 15:
        print("Got payload type: {}. Do not know how to decode.".format(
            blob_subtype_to_string(payload[0])))
    elif payload[0] == 16:
        print("Got payload type: {}. Do not know how to decode.".format(
            blob_subtype_to_string(payload[0])))
    else:
        raise RuntimeError(
            "Do not know how to decode payload with first byte {}".format(payload[0]))

    if decrypt and not supports_decrypt:
        raise RuntimeError(
            "--decrypt specified, but not supported for payload type {}".format(payload[0]))
    if dumpivs and not supports_dumpivs:
        raise RuntimeError(
            "--dumpivs specified, but not supported for payload type {}".format(payload[0]))


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("payload", help="Payload string. May be hex or base64")
    parser.add_argument("--base64", action="store_true",
                        help="Specify payload as base64")
    parser.add_argument("--hex", action="store_true",
                        help="Specify payload as hex")
    parser.add_argument("--infile", action="store_true",
                        help="Specify payload as a file. Input file may contain hex or base64")
    parser.add_argument(
        "--dumpivs", help="Dump all IVs as a string of hex data. This is useful for generating test data", action="store_true")
    parser.add_argument(
        "--decrypt", help="Decrypt data. Uses key material from the 'keys' directory.", action="store_true")
    args = parser.parse_args()
    input = args.payload
    if args.infile:
        with open(args.payload, "r") as file:
            input = file.read()
    dump_payload(input, encoding="base64" if args.base64 else "unknown",
                 dumpivs=args.dumpivs, decrypt=args.decrypt)


if __name__ == "__main__":
    main()
