# Shows an example of updating an unencrypted field on a collection configured with QE.
# Run with `python multiwrite.py`

import unittest

from bson.codec_options import CodecOptions
import bson.binary

from pymongo import MongoClient
from pymongo.encryption_options import AutoEncryptionOpts
from pymongo.encryption import ClientEncryption
import pymongo.errors

import os

class TestQEMultiWrite(unittest.TestCase):
    def setUp(self):
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

        # Ensure that two data keys cannot share the same keyAltName.
        key_vault.create_index(
            "keyAltNames",
            unique=True,
            partialFilterExpression={"keyAltNames": {"$exists": True}},
        )
        key_id = client_encryption.create_data_key("local")

        # Create the encrypted client.
        encrypted_fields_map = {
            "db.coll": {
                "fields": [
                    {
                        "path": "encryptedString",
                        "bsonType": "string",
                        "keyId": key_id,
                        "queries": [{"queryType": "equality"}],
                    }
                ],
            }
        }
        auto_encryption_opts = AutoEncryptionOpts(
            kms_providers,
            key_vault_namespace,
            encrypted_fields_map=encrypted_fields_map,
        )
        encryptedClient = MongoClient(auto_encryption_opts=auto_encryption_opts)
        encryptedClient["db"].drop_collection("coll")
        encryptedColl = encryptedClient["db"].create_collection("coll")

        # Test encryption works.
        encryptedColl.insert_one({"_id": 1, "encryptedString": "foo", "unencrypted": "bar"})
        unencryptedClient = MongoClient()
        unencryptedColl = unencryptedClient["db"]["coll"]
        self.assertTrue (isinstance(unencryptedColl.find_one()["encryptedString"], bson.binary.Binary))
        encryptedColl.delete_one({})

        # Add useful objects to `self`:
        self.encryptedClient = encryptedClient

    def testMultiUpdate(self):
        encryptedClient : MongoClient = self.encryptedClient
        encryptedColl = encryptedClient["db"]["coll"]
        
        unencryptedClient = MongoClient()
        unencryptedColl = unencryptedClient["db"]["coll"]

        # Insert documents.
        encryptedColl.insert_many([
            {"encryptedString": "foo1", "unencryptedString": "bar"},
            {"encryptedString": "foo2", "unencryptedString": "bar"}
        ])

        # Test a multi-document update. Expect error.
        with self.assertRaises(pymongo.errors.EncryptionError) as ctx:
            encryptedColl.update_many({}, {"$set": {"unencryptedString": "foo"}})
        self.assertIn ("Multi-document updates are not allowed with Queryable Encryption", str(ctx.exception))

        # Instead, use a client without auto encryption.
        unencryptedColl.update_many({}, {"$set": {"unencryptedString": "foo"}})
    
if __name__ == "__main__":
    unittest.main()

