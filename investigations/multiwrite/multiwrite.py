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
        encryptedColl.insert_one({"_id": 1, "encryptedString": "foo"})
        unencryptedClient = MongoClient()
        unencryptedColl = unencryptedClient["db"]["coll"]
        self.assertTrue (isinstance(unencryptedColl.find_one()["encryptedString"], bson.binary.Binary))
        encryptedColl.delete_one({})

        # Add useful objects to `self`:
        self.encryptedClient = encryptedClient

    def testMultiOps(self):
        encryptedClient : MongoClient = self.encryptedClient

        # Test a multi-statement insert.
        encryptedClient["db"].command({
            "insert": "coll",
            "documents": [
                {"encryptedString": "one"},
                {"encryptedString": "two"},
                {"encryptedString": "three"},
                {"encryptedString": "four"},
                {"encryptedString": "five"}
            ]
        })

        # Test a single-statement, single-document delete. Expect success.
        encryptedClient["db"].command({
            "delete" : "coll",
            "deletes" : [ {"q" : {"encryptedString" : "one"}, "limit" : 1} ]
        })
        self.assertEqual(encryptedClient["db"]["coll"].count_documents({}), 4)

        # Test a single-statement, multi-document delete. Expect success.
        encryptedClient["db"].command({
            "delete" : "coll",
            "deletes" : [ {"q" : {"encryptedString" : {"$in": ["two", "three"] }}, "limit" : 0} ]
        })
        self.assertEqual(encryptedClient["db"]["coll"].count_documents({}), 2)

        # Test a multi-statement delete. Expect error.
        with self.assertRaises(pymongo.errors.OperationFailure) as ctx:
            encryptedClient["db"].command({
                "delete" : "coll",
                "deletes" : [
                    {"q" : {}, "limit" : 1},
                    {"q" : {}, "limit" : 1}
                ]
            })
        self.assertIn ("Only single document deletes are permitted", str(ctx.exception))

        # Test a single-statement, single-document update. Expect success.
        encryptedClient["db"].command({
            "update" : "coll",
            "updates" : [
                {
                    "q" : {"encryptedString" : "four"},
                    "u" : { "$set": { "encryptedString": "four2" } },
                    "multi": False
                }
            ]
        })
        self.assertIsNotNone(encryptedClient["db"]["coll"].find_one({"encryptedString": "four2"}))

        # Test a single-statement, multi-document update. Expect error.
        with self.assertRaises(pymongo.errors.EncryptionError) as ctx:
            encryptedClient["db"].command({
                "update" : "coll",
                "updates" : [
                    {
                        "q" : {},
                        "u" : { "$set": { "encryptedString": "updated" } },
                        "multi": True
                    }
                ]
            })
        self.assertIn ("Multi-document updates are not allowed with Queryable Encryption", str(ctx.exception))

        # Test a multi-statement update. Expect error.
        with self.assertRaises(pymongo.errors.OperationFailure) as ctx:
            encryptedClient["db"].command({
                "update" : "coll",
                "updates" : [
                    {
                        "q" : {"encryptedString" : "four"},
                        "u" : { "$set": { "encryptedString": "four2" } },
                        "multi": False
                    },
                    {
                        "q" : {"encryptedString" : "four"},
                        "u" : { "$set": { "encryptedString": "four2" } },
                        "multi": False
                    }
                ]
            })
        self.assertIn ("Only single document updates are permitted", str(ctx.exception))
    
if __name__ == "__main__":
    unittest.main()

