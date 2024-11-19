"""
Benchmark running aggregate commands with auto encryption.

Times running 2000 aggregate commands. Runs 10 trials and prints the median.

Intended to answer: Does contacting query analysis twice produce significant overhead?

To test a custom build of libmongocrypt, export the following:
```
export PYMONGOCRYPT_LIB=/path/to/libmongocrypt.dylib
```

Tested by modifying libmongocrypt to request markings twice:

To test with crypt shared, pass:
```
export CRYPT_SHARED_PATH=/path/to/crypt_shared.dylib
```

With mongocryptd:
    With existing libmongocrypt: median time: 0.47s
    With modified libmongocrypt: median time: 0.68s
    Adds .11ms per operation.

With crypt_shared:
    With existing libmongocrypt: median time: 0.32s
    With modified libmongocrypt: median time: 0.34s
    Adds .01ms per operation.

"""

import os
from bson.codec_options import CodecOptions
from bson import json_util
from pymongo import MongoClient
from pymongo.encryption import Algorithm, ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts
from time import perf_counter


def create_json_schema_file(kms_providers, key_vault_namespace, key_vault_client):
    client_encryption = ClientEncryption(
        kms_providers,
        key_vault_namespace,
        key_vault_client,
        CodecOptions(),
    )

    # Create a new data key and json schema.
    data_key_id = client_encryption.create_data_key(
        "local", key_alt_names=["pymongo_encryption_example_1"]
    )
    schema = {
        "properties": {
            "encryptedField": {
                "encrypt": {
                    "keyId": [data_key_id],
                    "bsonType": "string",
                    "algorithm": Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic,
                }
            }
        },
        "bsonType": "object",
    }

    json_schema_string = json_util.dumps(
        schema, json_options=json_util.CANONICAL_JSON_OPTIONS
    )

    with open("jsonSchema.json", "w") as file:
        file.write(json_schema_string)


def main():
    # The MongoDB namespace (db.collection) used to store the
    # encrypted documents in this example.
    encrypted_namespace = "db.encrypted"

    # This must be the same master key that was used to create
    # the encryption key.
    local_master_key = os.urandom(96)
    kms_providers = {"local": {"key": local_master_key}}

    # The MongoDB namespace (db.collection) used to store
    # the encryption data keys.
    key_vault_namespace = "encryption.__pymongoTestKeyVault"
    key_vault_db_name, key_vault_coll_name = key_vault_namespace.split(".", 1)

    # The MongoClient used to access the key vault (key_vault_namespace).
    key_vault_client = MongoClient()
    key_vault = key_vault_client[key_vault_db_name][key_vault_coll_name]
    # Ensure that two data keys cannot share the same keyAltName.
    key_vault.drop()
    key_vault.create_index(
        "keyAltNames",
        unique=True,
        partialFilterExpression={"keyAltNames": {"$exists": True}},
    )

    create_json_schema_file(kms_providers, key_vault_namespace, key_vault_client)

    # Load the JSON Schema and construct the local schema_map option.
    with open("jsonSchema.json", "r") as file:
        json_schema_string = file.read()
    json_schema = json_util.loads(json_schema_string)
    schema_map = {encrypted_namespace: json_schema}


    if "CRYPT_SHARED_PATH" in os.environ:
        auto_encryption_opts = AutoEncryptionOpts(
           kms_providers, key_vault_namespace, schema_map=schema_map, mongocryptd_bypass_spawn=True, crypt_shared_lib_path=os.environ["CRYPT_SHARED_PATH"], crypt_shared_lib_required=True,
        )
    else:
        auto_encryption_opts = AutoEncryptionOpts(
           kms_providers, key_vault_namespace, schema_map=schema_map, mongocryptd_bypass_spawn=True
        )

    encrypted_client = MongoClient(auto_encryption_opts=auto_encryption_opts)
    db_name, coll_name = encrypted_namespace.split(".", 1)
    coll = encrypted_client[db_name][coll_name]
    # Clear old data
    coll.drop()

    # Do 10 trials of 2000 aggregate ops.
    times = []
    for trial in range (10):
        print ("trial: {}".format(trial))
        start = perf_counter()
        for _ in range (2000):
            cursor = coll.aggregate([{
                "$match": {}
            }])
            for doc in cursor:
                print (doc)
        end = perf_counter()
        times.append(end - start)
    times.sort()
    median = times[len(times) // 2]
    print ("median time: {:.02f}".format(median))

if __name__ == "__main__":
    main()
