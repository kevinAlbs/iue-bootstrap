# decode_payload

Decode In-Use Encryption (IUE) payloads.

IUE consists of Client-Side Field Level Encryption (CSFLE) and Queryable Encryption (QE).
IUE uses the BSON binary subtype 6 for payloads.

# Example Usage

```bash
$ uv run decode_payload.py ADgAAAAQYQABAAAABWtpABAAAAAEYWFhYWFhYWFhYWFhYWFhYQJ2AAwAAAA0NTctNTUtNTQ2MgAA
FLE1EncryptionPlaceholder
$ uv run decode_payload.py --json ADgAAAAQYQABAAAABWtpABAAAAAEYWFhYWFhYWFhYWFhYWFhYQJ2AAwAAAA0NTctNTUtNTQ2MgAA
{
    "name": "FLE1EncryptionPlaceholder",
    "dump": {
        "a": 1,
        "ki": {
            "$binary": {
                "base64": "YWFhYWFhYWFhYWFhYWFhYQ==",
                "subType": "04"
            }
        },
        "v": "457-55-5462"
    }
}
```

# Explanation

FLE1 payloads are for CSFLE. FLE2 payloads are for QE. See [Naming](https://github.com/mongodb/specifications/blob/9d0d3f0042a8cf5faeb47ae7765716151bfca9ef/source/client-side-encryption/client-side-encryption.md#naming).

## **FLE1EncryptionPlaceholder (0)**

| Created by | mongocryptd / crypt\_shared |
| :---- | :---- |
| **Intended for** | libmongocrypt |
| **References** | [Spec](https://github.com/mongodb/specifications/blob/9d0d3f0042a8cf5faeb47ae7765716151bfca9ef/source/bson-binary-encrypted/binary-encrypted.md) [Server IDL](https://github.com/mongodb/mongo/blob/6ec0bf4dd0c59fdfcacaaa36d3b7cb374da3e243/src/mongo/crypto/fle_field_schema.idl#L134-L159) / [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mongocrypt-marking.c#L48-L143) |

## **FLE1DeterministicEncryptedValue (1)**

| Created by | libmongocrypt |
| :---- | :---- |
| **Intended for** | mongod / mongos |
| **References** | [Spec](https://github.com/mongodb/specifications/blob/9d0d3f0042a8cf5faeb47ae7765716151bfca9ef/source/bson-binary-encrypted/binary-encrypted.md) / [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mongocrypt-ciphertext-private.h#L31-L36) |

## **FLE1RandomEncryptedValue (2)**

| Created by | libmongocrypt |
| :---- | :---- |
| **Intended for** | mongod / mongos |
| **References** | [Spec](https://github.com/mongodb/specifications/blob/9d0d3f0042a8cf5faeb47ae7765716151bfca9ef/source/bson-binary-encrypted/binary-encrypted.md) / [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mongocrypt-ciphertext-private.h#L31-L36) |

## **FLE2EncryptionPlaceholder (3)**

| Created by | mongocryptd / crypt\_shared |
| :---- | :---- |
| **Intended for** | libmongocrypt |
| **References** | [Server IDL](https://github.com/mongodb/mongo/blob/6ec0bf4dd0c59fdfcacaaa36d3b7cb374da3e243/src/mongo/crypto/fle_field_schema.idl#L161-L198) / [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-encryption-placeholder-private.h#L219-L228) |

## **FLE2InsertUpdatePayload (4)**

| Created by | libmongocrypt |
| :---- | :---- |
| **Intended for** | mongocryptd / crypt\_shared |
| **References** | [Server IDL](https://github.com/mongodb/mongo/blob/443b0594b28476e3f78e0c5923fcebf2c7abd19b/src/mongo/crypto/fle_field_schema.idl#L232-L272) / [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-insert-update-payload-private.h#L64-L76) |

## **FLE2FindEqualityPayload (5)**

| Created by | libmongocrypt |
| :---- | :---- |
| **Intended for** | mongod / mongos |
| **References** | [Server IDL](https://github.com/mongodb/mongo/blob/443b0594b28476e3f78e0c5923fcebf2c7abd19b/src/mongo/crypto/fle_field_schema.idl#L334-L359) / [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-find-equality-payload-private.h#L24-L30) |

## **FLE2UnindexedEncryptedValue (6)**

| Created by | libmongocrypt |
| :---- | :---- |
| **Intended for** | mongod / mongos |
| **References** | [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-payload-uev-private.h#L24-L44) |

## **FLE2IndexedEqualityEncryptedValue (7)**

| Created by | mongod / mongos |
| :---- | :---- |
| **Intended for** | libmongocrypt |
| **References** | [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-payload-iev-private.h#L38-L66) |

## **FLE2IndexedRangeEncryptedValue (9)**

| Created by | mongod / mongos |
| :---- | :---- |
| **Intended for** | libmongocrypt |
| **References** | [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-payload-iev-private.h#L68-L84) |

## **FLE2FindRangePayload (10)**

| Created by | libmongocrypt |
| :---- | :---- |
| **Intended for** | mongod / mongos |
| **References** | [Server IDL](https://github.com/mongodb/mongo/blob/443b0594b28476e3f78e0c5923fcebf2c7abd19b/src/mongo/crypto/fle_field_schema.idl#L447-L466) / [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-find-range-payload-private.h#L53-L67) |

## **FLE2InsertUpdatePayloadV2 (11)**

| Created by | libmongocrypt |
| :---- | :---- |
| **Intended for** | mongod / mongos |
| **References** | [Server IDL](https://github.com/10gen/mongo/blob/31715bfe7e87f2908670654745cbf2df3db1796e/src/mongo/crypto/fle_field_schema.idl#L326-L404) / [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-insert-update-payload-private-v2.h#L107-L131) |

## **FLE2FindEqualityPayloadV2 (12)**

| Created by | libmongocrypt |
| :---- | :---- |
| **Intended for** | mongod / mongos |
| **References** | [Server IDL](https://github.com/10gen/mongo/blob/31715bfe7e87f2908670654745cbf2df3db1796e/src/mongo/crypto/fle_field_schema.idl#L406-L426) / [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-find-equality-payload-private-v2.h#L24-L29) |

## **FLE2FindRangePayloadV2 (13)**

| Created by | libmongocrypt |
| :---- | :---- |
| **Intended for** | mongod / mongos |
| **References** | [Server IDL](https://github.com/10gen/mongo/blob/31715bfe7e87f2908670654745cbf2df3db1796e/src/mongo/crypto/fle_field_schema.idl#L458-L505) / [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-find-range-payload-private-v2.h#L58-L78) |

## **FLE2EqualityIndexedValueV2 (14)**

| Created by | mongod / mongos |
| :---- | :---- |
| **Intended for** | libmongocrypt |
| **References** | [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-payload-iev-private-v2.h#L42-L62) |

## **FLE2RangeIndexedValueV2 (15)**

| Created by | mongod / mongos |
| :---- | :---- |
| **Intended for** | libmongocrypt |
| **References** | [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-payload-iev-private-v2.h#L65-L74) |

## **FLE2UnindexedEncryptedValueV2 (16)**

| Created by | libmongocrypt |
| :---- | :---- |
| **Intended for** | mongod / mongos |
| **References** | [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-payload-uev-v2-private.h#L24-L44) |

## **FLE2IndexedTextEncryptedValue (17)**

| Created by | mongod / mongos |
| :---- | :---- |
| **Intended for** | libmongocrypt |
| **References** | [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-payload-iev-private-v2.h#L81-L102) |

## **FLE2FindTextPayload (18)**

| Created by | libmongocrypt |
| :---- | :---- |
| **Intended for** | mongod / mongos |
| **References** | [Server IDL](https://github.com/10gen/mongo/blob/31715bfe7e87f2908670654745cbf2df3db1796e/src/mongo/crypto/fle_field_schema.idl#L815-L850) / [libmongocrypt](https://github.com/mongodb/libmongocrypt/blob/9631ac9d6da645c1de1e9388832b95301a3107ec/src/mc-fle2-find-text-payload-private.h#L92-L112) |
