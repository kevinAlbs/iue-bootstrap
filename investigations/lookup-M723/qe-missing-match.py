# Test $lookup behavior on pre-8.1 servers.
# Self-lookup and explicit encryption may fail to match QE documents in sub-pipelines.
# Run with `python qe-missing-match.py`

import unittest

from bson.codec_options import CodecOptions
import bson.binary

from pymongo import MongoClient
from pymongo.encryption_options import AutoEncryptionOpts
from pymongo.encryption import ClientEncryption, Algorithm

import os


class TestQEMissingMatch(unittest.TestCase):
    def setUp(self):
        """
        Creates a collection `db.qe` and `db.qe2` with Queryable Encryption enabled on the `qe` and `qe2` fields.
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
            "db.qe": {
                "fields": [
                    {
                        "path": "qe",
                        "bsonType": "string",
                        "keyId": key_id,
                        "queries": [{"queryType": "equality", "contention": 0}],
                    }
                ],
            },
            "db.qe2": {
                "fields": [
                    {
                        "path": "qe2",
                        "bsonType": "string",
                        "keyId": key_id,
                        "queries": [{"queryType": "equality", "contention": 0}],
                    }
                ],
            },
        }
        auto_encryption_opts = AutoEncryptionOpts(
            kms_providers,
            key_vault_namespace,
            encrypted_fields_map=encrypted_fields_map,
        )
        auto_client = MongoClient(auto_encryption_opts=auto_encryption_opts)
        auto_client.drop_database("db")
        qe = auto_client["db"].create_collection("qe")
        qe.insert_one({"qe": "qe"})
        qe = auto_client["db"].create_collection("qe2")
        qe.insert_one({"qe2": "qe2"})
        plain_client = MongoClient()
        self.assertTrue(
            isinstance(plain_client["db"]["qe"].find_one()["qe"], bson.binary.Binary)
        )
        self.assertTrue(
            isinstance(plain_client["db"]["qe2"].find_one()["qe2"], bson.binary.Binary)
        )

        # Create a client with bypassAutoEncryption to support explicit encryption:
        explicit_opts = AutoEncryptionOpts(
            kms_providers,
            key_vault_namespace,
            encrypted_fields_map=encrypted_fields_map,
            bypass_auto_encryption=True,
        )
        self.explicit_client = MongoClient(auto_encryption_opts=explicit_opts)
        self.client_encryption = client_encryption
        self.key_vault_client = key_vault_client
        self.key_id = key_id
        self.auto_client = auto_client
        plain_client.close()

    def tearDown(self):
        self.auto_client.close()
        self.explicit_client.close()
        self.client_encryption.close()
        self.key_vault_client.close()
        return super().tearDown()

    def testSelfLookup(self):
        # "db.qe" is configured with QE and contains `{ "qe": "qe" }`. "qe" is encrypted.
        pipeline = [
            {
                "$lookup": {
                    "from": "qe",
                    "pipeline": [
                        {"$match": {"qe": "qe"}}
                    ],
                    "as": "matched",
                }
            },
            {"$project": {"_id": 0, "__safeContent__": 0}},
        ]
        got = self.auto_client["db"]["qe"].aggregate(pipeline).to_list()
        self.assertEqual(got, [{"qe": "qe", "matched": []}])
        # Does not match { "qe": "qe" }!
    def testExplicitLookup(self):
        # "db.qe2" is configured with QE and contains `{ "qe2": "qe2" }`. "qe2" is encrypted.
        payload = self.client_encryption.encrypt(
            "qe2", algorithm=Algorithm.INDEXED, contention_factor=0, key_id=self.key_id
        )
        pipeline = [
            {
                "$lookup": {
                    "from": "qe2",
                    "pipeline": [
                        {"$match": {"qe2": payload}},
                    ],
                    "as": "matched",
                }
            },
            {"$project": {"_id": 0, "__safeContent__": 0}},
        ]
        got = self.explicit_client["db"]["qe"].aggregate(pipeline).to_list()
        self.assertEqual(got, [{"qe": "qe", "matched": []}])
        # Does not match { "qe2": "qe2" }!

if __name__ == "__main__":
    unittest.main()
