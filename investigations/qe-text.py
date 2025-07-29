# /// script
# dependencies = [
#   "pymongo[encryption]",
# ]
# ///

"""
Test various QE Text behavior.
Run with: `uv run qe-text.py`
"""

import os
from bson.codec_options import CodecOptions
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts
import pymongo.errors
import unittest

class test_qe_text (unittest.TestCase):
    def setUp(self):
        """
        Create a new collection with QE text fields.
        """
        local_master_key = os.urandom(96)
        kms_providers = {"local": {"key": local_master_key}}
        key_vault_namespace = "keyvault.datakeys"
        key_vault_client = MongoClient()
        client_encryption = ClientEncryption(
            kms_providers, key_vault_namespace, key_vault_client, CodecOptions()
        )
        key_vault = key_vault_client["keyvault"]["datakeys"]
        key_vault.drop()
        key_id = client_encryption.create_data_key("local")
        key_id2 = client_encryption.create_data_key("local")

        encrypted_fields_map = {
            "db.coll": {
                "fields": [
                    {
                        "path": "secret",
                        "keyId": key_id,
                        "bsonType": "string",
                        "queries": [
                            {
                                "queryType": "prefixPreview",
                                "strMinQueryLength": 2,
                                "strMaxQueryLength": 10,
                                "caseSensitive": True,
                                "diacriticSensitive": True,
                            },
                            {
                                "queryType": "suffixPreview",
                                "strMinQueryLength": 2,
                                "strMaxQueryLength": 10,
                                "caseSensitive": True,
                                "diacriticSensitive": True,
                            }
                        ],
                    },
                    {
                        "path": "secretSubstring",
                        "keyId": key_id2,
                        "bsonType": "string",
                        "queries": [
                            {
                                "queryType": "substringPreview",
                                "strMaxLength": 10,
                                "strMinQueryLength": 2,
                                "strMaxQueryLength": 10,
                                "caseSensitive": True,
                                "diacriticSensitive": True,
                            }
                        ],
                    }
                ]
            }
        }

        auto_encryption_opts = AutoEncryptionOpts(
            kms_providers,
            key_vault_namespace,
            encrypted_fields_map=encrypted_fields_map,
            mongocryptd_bypass_spawn=True,  # Already running
        )
        client = MongoClient(auto_encryption_opts=auto_encryption_opts)
        db = client["db"]
        db.drop_collection("coll")

        # Persist client and collection for use in tests.
        self.coll = db.create_collection("coll")
        key_vault_client.close()

    def tearDown(self):
        self.coll.database.client.close()
        return super().tearDown()

    def test(self):
        # Insert and query with prefix:
        self.coll.insert_one({"_id": 1, "secret": "foobar"})
        got = self.coll.find_one(
            filter={"$expr": {"$encStrStartsWith": {"input": "$secret", "prefix": "foo"}}},
            projection={"__safeContent__": 0},
        )
        self.assertEqual (got, {"_id": 1, "secret": "foobar"})

        # Query with prefix longer than strMaxQueryLength (10):
        with self.assertRaises(pymongo.errors.EncryptionError) as ctx:
            self.coll.find_one(
                filter={"$expr": {"$encStrStartsWith": {"input": "$secret", "prefix": "too-long-too-long"}}},
                projection={"__safeContent__": 0},
            )
        self.assertIn ("longer than the maximum query length", str(ctx.exception))

        # Query with prefix shorter than strMinQueryLength (2):
        with self.assertRaises(pymongo.errors.EncryptionError) as ctx:
            self.coll.find_one(
                filter={"$expr": {"$encStrStartsWith": {"input": "$secret", "prefix": "f"}}},
                projection={"__safeContent__": 0},
            )
        self.assertIn ("shorter than the minimum query length", str(ctx.exception))

        # Insert a substring longer than strMaxLength:
        with self.assertRaises(pymongo.errors.EncryptionError):
            self.coll.insert_one({"_id": 2, "secretSubstring": "foobartoolong"})

if __name__ == "__main__":
    unittest.main()
