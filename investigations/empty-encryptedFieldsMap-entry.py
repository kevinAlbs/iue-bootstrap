"""
An example of configuring EncryptedFieldsMap with an empty entry for `db.c2`.
Prevents libmongocrypt from checking for a server-side schema of `db.c2`.
"""
from bson.codec_options import CodecOptions
import bson.binary

from pymongo import MongoClient
from pymongo.encryption_options import AutoEncryptionOpts
from pymongo.encryption import ClientEncryption
import os

def main():
        """
        Creates a collection `db.coll` with Queryable Encryption enabled on the `encryptedString` field.
        """
        kms_providers = {"local": {"key": os.urandom(96)}}
        key_vault_namespace = "keyvault.datakeys"
        key_vault_client = MongoClient()

        # Create data key.
        client_encryption = ClientEncryption(
            kms_providers, key_vault_namespace, key_vault_client, CodecOptions()
        )
        key_vault = key_vault_client["keyvault"]["datakeys"]
        key_vault.drop()
        key_id = client_encryption.create_data_key("local")

        # Create the encrypted client.
        encrypted_fields_map = {
            "db.c1": {
                "fields": [
                    {
                        "path": "encryptedString",
                        "bsonType": "string",
                        "keyId": key_id,
                        "queries": [{"queryType": "equality"}],
                    }
                ],
            },
            "db.c2": {} # Use empty entry for db.c2.
        }
        auto_encryption_opts = AutoEncryptionOpts(
            kms_providers,
            key_vault_namespace,
            encrypted_fields_map=encrypted_fields_map,
        )
        encryptedClient = MongoClient(auto_encryption_opts=auto_encryption_opts)
        encryptedClient["db"].drop_collection("c1")
        encryptedColl = encryptedClient["db"].create_collection("c1")

        # Test encryption works.
        encryptedColl.insert_one({"_id": 1, "encryptedString": "foo"})
        unencryptedClient = MongoClient()
        unencryptedColl = unencryptedClient["db"]["c1"]
        assert (isinstance(unencryptedColl.find_one()["encryptedString"], bson.binary.Binary))
        encryptedColl.delete_one({})

if __name__ == "__main__":
    main()

