This directory contains `run_cmd.py` to send a command to `mongocryptd`, and sample commands in `tests`.

Example use:
```bash
# Assume mongocryptd is running on port 27020
cat tests/find.json | python run_cmd.py --port 27020 --db db
```
Produces this output with `encrypted` as an encryption placeholder:
```json
{
    "hasEncryptionPlaceholders": true,
    "schemaRequiresEncryption": true,
    "result": {
        "find": "test",
        "filter": {
            "encrypted": {
                "$eq": {
                    "$binary": {
                        "base64": "A1gAAAAQdAACAAAAEGEAAgAAAAVraQAQAAAABBI0VngSNJh2EjQSNFZ4kBIFa3UAEAAAAAQSNFZ4EjSYdhI0EjRWeJASEHYAewAAABJjbQAAAAAAAAAAAAA=",
                        "subType": "06"
                    }
                }
            }
        },
        "encryptionInformation": {
            "type": {
                "$numberInt": "1"
            },
            "schema": {
                "db.test": {
                    "escCollection": "enxcol_.test.esc",
                    "ecocCollection": "enxcol_.test.ecoc",
                    "fields": [
                        {
                            "keyId": {
                                "$binary": {
                                    "base64": "EjRWeBI0mHYSNBI0VniQEg==",
                                    "subType": "04"
                                }
                            },
                            "path": "encrypted",
                            "bsonType": "int",
                            "queries": {
                                "queryType": "equality",
                                "contention": {
                                    "$numberInt": "0"
                                }
                            }
                        }
                    ]
                }
            }
        }
    },
    "ok": {
        "$numberDouble": "1.0"
    }
}
```

The payload can be identified with the (likely outdated) [dump_payload](https://github.com/kevinAlbs/dump_payload) tool:

```bash
python dump_payload A1gAAAAQdAACAAAAEGEAAgAAAAVraQAQAAAABBI0VngSNJh2EjQSNFZ4kBIFa3UAEAAAAAQSNFZ4EjSYdhI0EjRWeJASEHYAewAAABJjbQAAAAAAAAAAAAA=
```

Produces this output:
```
blob_subtype: 3 (FLE2EncryptionPlaceholder)
t (type): 2 (kFind)
a (algorithm): 2 (Indexed Equality)
ki (IndexKeyId): b'\x124Vx\x124\x98v\x124\x124Vx\x90\x12' 
ku (UserKeyId): b'\x124Vx\x124\x98v\x124\x124Vx\x90\x12' 
v (value): 123 
cm (max contention counter): 0 
```
