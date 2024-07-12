A utility for testing the [Automatic Encryption Shared Library](https://www.mongodb.com/docs/manual/core/queryable-encryption/reference/shared-library/).

Examples:

```
$ python markup.py --version --libpath ~/bin/crypt_shared-6.0.0/lib/mongo_crypt_v1.dylib 
mongo_crypt_v1-dev-6.0.0
```

```
$ cat example-input.json | python markup.py --libpath ~/bin/crypt_shared-6.0.0/lib/mongo_crypt_v1.dylib 
{
    "hasEncryptionPlaceholders": true,
    "schemaRequiresEncryption": true,
    "result": {
        "find": "test",
        "filter": {
            "value": {
                "$eq": {
                    "$binary": {
                        "base64": "A1gAAAAQdAACAAAAEGEAAgAAAAVraQAQAAAABBI0VngSNJh2EjQSNFZ4kBIFa3UAEAAAAAQSNFZ4EjSYdhI0EjRWeJASEHYAQOIBABJjbQAAAAAAAAAAAAA=",
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
                    "escCollection": "esc",
                    "eccCollection": "ecc",
                    "ecocCollection": "ecoc",
                    "fields": [
                        {
                            "keyId": {
                                "$binary": {
                                    "base64": "EjRWeBI0mHYSNBI0VniQEg==",
                                    "subType": "04"
                                }
                            },
                            "path": "value",
                            "bsonType": "int",
                            "queries": {
                                "queryType": "equality",
                                "contention": {
                                    "$numberLong": "0"
                                }
                            }
                        }
                    ]
                }
            }
        }
    }
}
```

`markup.py` depends on cffi. Use `pip install cffi`.
