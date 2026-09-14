# Run with: uv run explicit-s3.py
#
# Encrypt a file locally with CSFLE explicit encryption, store the ciphertext in
# S3, and store only a pointer + metadata in MongoDB. Decrypt by fetching the
# object back from S3 and calling ClientEncryption.decrypt().
#
# MongoDB is used for the key vault and the metadata collection. The payload
# itself never goes to the server.
#
# Environment:
#   S3_BUCKET      required, name of an existing bucket
#   MONGODB_URI    optional, defaults to mongodb://localhost:27017
#
# /// script
# dependencies = [
#   "pymongo[encryption]",
#   "boto3",
# ]
# ///

import os
import uuid

import boto3
from bson.binary import Binary
from pymongo import MongoClient
from pymongo.encryption import Algorithm, ClientEncryption


def main():
    bucket = os.environ["S3_BUCKET"]
    s3 = boto3.client("s3")

    # A local master key. In production use AWS KMS (or another KMS provider)
    # so the master key is never on the application host.
    local_master_key = os.urandom(96)
    kms_providers = {"local": {"key": local_master_key}}
    key_vault_namespace = "keyvault.datakeys"
    key_vault_db_name, key_vault_coll_name = key_vault_namespace.split(".", 1)

    client = MongoClient(os.environ.get("MONGODB_URI", "mongodb://localhost:27017"))
    key_vault = client[key_vault_db_name][key_vault_coll_name]

    client_encryption = ClientEncryption(
        kms_providers,
        key_vault_namespace,
        client,
        client.codec_options,
    )

    # One data key per tenant/file/whatever granularity you want to re-key at.
    key_id = client_encryption.create_data_key("local")

    # ---- Encrypt + upload -------------------------------------------------
    plaintext = b"the contents of some file the customer wants protected"

    # Explicit encryption operates on a BSON value. A file is a BSON binary.
    # Use the Random algorithm: the blob is not queryable, and Deterministic
    # would leak equality between identical files.
    ciphertext = client_encryption.encrypt(
        Binary(plaintext),
        Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random,
        key_id=key_id,
    )
    # `ciphertext` is a BSON binary subtype 6 blob: it carries the key id and
    # the original BSON type, so decrypt() needs nothing but the key vault.
    object_key = f"encrypted/{uuid.uuid4()}"
    s3.put_object(Bucket=bucket, Key=object_key, Body=bytes(ciphertext))

    # Only the pointer and non-sensitive metadata go to MongoDB.
    metadata = client.test.files.insert_one(
        {
            "bucket": bucket,
            "objectKey": object_key,
            "keyId": key_id,
            "filename": "claim-12345.pdf",
            "contentType": "application/pdf",
            "sizeBytes": len(plaintext),
        }
    )
    print(f"stored s3://{bucket}/{object_key}, metadata _id={metadata.inserted_id}")

    # ---- Look up + download + decrypt -------------------------------------
    doc = client.test.files.find_one({"_id": metadata.inserted_id})
    assert doc is not None
    body = s3.get_object(Bucket=doc["bucket"], Key=doc["objectKey"])["Body"].read()
    decrypted = client_encryption.decrypt(Binary(body, 6))
    assert bytes(decrypted) == plaintext
    print(f"decrypted {len(decrypted)} bytes: {decrypted!r}")

    # Cleanup.
    s3.delete_object(Bucket=bucket, Key=object_key)
    client.test.files.delete_one({"_id": metadata.inserted_id})
    key_vault.delete_one({"_id": key_id})
    client_encryption.close()
    client.close()


if __name__ == "__main__":
    main()
